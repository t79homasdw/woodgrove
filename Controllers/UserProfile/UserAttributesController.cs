using Azure.Identity;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using Microsoft.Identity.Client;
using System.Dynamic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using woodgrovedemo.Helpers;
using woodgrovedemo.Models;

namespace woodgrovedemo.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class UserAttributesController : ControllerBase
{

    // Dependency injection
    private readonly IConfiguration _configuration;
    private TelemetryClient _telemetry;
    private readonly GraphServiceClient _graphServiceClient;
    readonly IAuthorizationHeaderProvider _authorizationHeaderProvider;
    private string ExtensionAttributes { get; set; } = "";

    public static X509Certificate2 ReadCertificate(string certificateThumbprint)
    {
        if (string.IsNullOrWhiteSpace(certificateThumbprint))
        {
            throw new ArgumentException("certificateThumbprint should not be empty. Please set the certificateThumbprint setting in the appsettings.json", "certificateThumbprint");
        }
        CertificateDescription certificateDescription = CertificateDescription.FromStoreWithThumbprint(
             certificateThumbprint,
             StoreLocation.CurrentUser,
             StoreName.My);

        DefaultCertificateLoader defaultCertificateLoader = new DefaultCertificateLoader();
        defaultCertificateLoader.LoadIfNeeded(certificateDescription);

        if (certificateDescription.Certificate == null)
        {
            throw new Exception("Cannot find the certificate.");
        }

        return certificateDescription.Certificate;
    }


    public UserAttributesController(IConfiguration configuration, TelemetryClient telemetry, GraphServiceClient graphServiceClient, IAuthorizationHeaderProvider authorizationHeaderProvider)
    {
        _configuration = configuration;
        _telemetry = telemetry;

        // Get the app settings
        ExtensionAttributes = _configuration.GetSection("MicrosoftGraph:ExtensionAttributes").Value ?? string.Empty;
        _graphServiceClient = graphServiceClient;
        _authorizationHeaderProvider = authorizationHeaderProvider;
    }

    [HttpGet]
    public async Task<IActionResult> GetAsync()
    {
        UserAttributes att = new UserAttributes();

        try
        {
            User? profile = await _graphServiceClient.Me.GetAsync(requestConfiguration =>
            {
                requestConfiguration.QueryParameters.Select = new string[]
                {
                "Id", "identities", "displayName", "GivenName", "Surname",
                "Country", "City", "AccountEnabled", "CreatedDateTime",
                "lastPasswordChangeDateTime", $"{ExtensionAttributes}_SpecialDiet"
                };
                requestConfiguration.QueryParameters.Expand = new string[] { "Extensions" };
            });

            //{
            //    requestConfiguration.QueryParameters.Select = new string[] { "Id", "identities", "displayName", "GivenName", "Surname", "Country", "City", "AccountEnabled", "CreatedDateTime", "lastPasswordChangeDateTime", $"{ExtensionAttributes}_SpecialDiet" };
            //    requestConfiguration.QueryParameters.Expand = new string[] { "Extensions" };
            //});

            if (profile == null)
            {
                att.ErrorMessage = "Profile data could not be retrieved.";
                return Ok(att);
            }

            // Populate the user's attributes
            att.ObjectId = profile.Id!;
            att.DisplayName = profile.DisplayName ?? "";
            att.Surname = profile.Surname ?? "";
            att.GivenName = profile.GivenName ?? "";
            att.Country = profile.Country ?? "";
            att.City = profile.City ?? "";

            if (profile!.AccountEnabled != null)
                att.AccountEnabled = (bool)profile!.AccountEnabled;

            // Get the special diet from the extension attributes
            object? specialDiet;
            if (profile.AdditionalData.TryGetValue($"{ExtensionAttributes}_SpecialDiet", out specialDiet))
            {
                if (specialDiet != null)
                {
                    // Convert the special diet to a string if it's not already
                    att.SpecialDiet = specialDiet.ToString() ?? string.Empty;
                }
            }


            // Get the account creation time
            if (profile.CreatedDateTime != null)
            {
                att.CreatedDateTime = profile.CreatedDateTime.ToString();
            }

            // Get the last time user changed their password
            if (profile.LastPasswordChangeDateTime != null)
            {
                att.LastPasswordChangeDateTime = profile.LastPasswordChangeDateTime.ToString();
            }
            else
            {
                att.LastPasswordChangeDateTime = "Data is not available. It might be because you sign-in with a federated account, or email and one time passcode.";
            }

            return Ok(att);
        }
        catch (ODataError odataError)
        {
            // Detect claims challenge (like MFA, incremental consent, CA)
            if (!string.IsNullOrEmpty(odataError.Error?.Message) &&
                odataError.Error.Message.Contains("claims", StringComparison.OrdinalIgnoreCase))
            {
                // Extract the claims from the error
                if (odataError.Error.AdditionalData != null &&
                    odataError.Error.AdditionalData.TryGetValue("claims", out var claimsObj) &&
                    claimsObj is string claims)
                {
                    // Trigger an interactive sign-in with claims
                    var props = new AuthenticationProperties();
                    props.Items["claims"] = claims;
                    props.RedirectUri = Url.Action("Index", "Home"); // or wherever you want to go back

                    return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
                }
            }

            att.ErrorMessage = $"Can't read the profile due to: {odataError.Error!.Message} Code: {odataError.Error.Code}";
            AppInsights.TrackException(_telemetry, odataError, "ReadProfile");
        }
        catch (Exception ex)
        {
            string error = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
            att.ErrorMessage = $"Can't read the profile due to: {error}";
            AppInsights.TrackException(_telemetry, ex, "ReadProfile");
        }

        return Ok(att);
    }

    [HttpPost]
    public async Task<IActionResult> OnPostAsync([FromForm] UserAttributes att)
    {

        _telemetry.TrackPageView("Profile:Update");

        // Read app settings
        string baseUrl = _configuration.GetSection("GraphApiMiddleware:BaseUrl").Value!;
        string[] scopes = _configuration.GetSection("GraphApiMiddleware:Scopes")!.Get<string[]>()!;
        string endpoint = _configuration.GetSection("GraphApiMiddleware:Endpoint").Value!;
        string? certificateThumbprint = _configuration.GetSection("MicrosoftGraph:CertificateThumbprint").Value;
        string? clientId = _configuration.GetSection("GraphApiMiddleware:ClientId").Value!;

        // Check the scopes application settings
        if (scopes == null)
        {
            att.ErrorMessage = "The GraphApiMiddleware:Scopes application setting is misconfigured or missing. Use the array format: [\"Account.Payment\", \"Account.Purchases\"]";
            return Ok();
        }

        // Check the base URL application settings
        if (string.IsNullOrEmpty(baseUrl))
        {
            att.ErrorMessage = "The GraphApiMiddleware:BaseUrl application setting is misconfigured or missing. Check out your applications' scope base URL in Microsoft Entra admin center. For example: api://12345678-0000-0000-0000-000000000000";
            return Ok();
        }

        // Check the endpoint application settings
        if (string.IsNullOrEmpty(endpoint))
        {
            att.ErrorMessage = "The GraphApiMiddleware:Endpoint application setting is misconfigured or missing.";
            return Ok();
        }

        // Set the scope full URL (temporary workaround should be fix)
        for (int i = 0; i < scopes.Length; i++)
        {
            scopes[i] = $"{baseUrl}/{scopes[i]}";
        }
        //scopes[0] = "api://claciamdemo.ciamlogin.com/clamiddle/.default";

        try
        {
            // Get an access token to call the Graph middleware API
            //var accessToken = await _authorizationHeaderProvider.CreateAuthorizationHeaderForUserAsync(scopes);
            var bearerToken = await _authorizationHeaderProvider.CreateAuthorizationHeaderForUserAsync(scopes);
            var token = bearerToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? bearerToken.Substring("Bearer ".Length): bearerToken;
            X509Certificate2 certificate = ReadCertificate(certificateThumbprint);

            //This code can be used to create a confidential client application token.  Note that in CIAM Tenants this is not currently supported.  Use the authorization header provider instead.
            
            //var app = ConfidentialClientApplicationBuilder.Create(clientId)
            //    .WithCertificate(certificate)
            //    .WithAuthority("https://InfraPracticeExtID.ciamlogin.com/47a08a92-c81e-4bb4-8276-316803a3fa35/v2.0/?p=CLA_Test")
            //    .WithAuthority("https://login.microsoftonline.com/47a08a92-c81e-4bb4-8276-316803a3fa35")
            //    .Build();

            //var result = await app.AcquireTokenForClient(new[] {
            //"https://graph.microsoft.com/.default"
            //}).ExecuteAsync();

            //string accessToken = result.AccessToken;



            // Use the access token to call the Graph middleware API.
            HttpClient client = new HttpClient();

            //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var formContent = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("ObjectId", att.ObjectId ?? string.Empty),
                    new KeyValuePair<string, string>("City", att.City ?? string.Empty),
                    new KeyValuePair<string, string>("Country", att.Country ?? string.Empty),
                    new KeyValuePair<string, string>("DisplayName", att.DisplayName ?? string.Empty),
                    new KeyValuePair<string, string>("GivenName", att.GivenName ?? string.Empty),
                    new KeyValuePair<string, string>("SpecialDiet", att.SpecialDiet ?? string.Empty),
                    new KeyValuePair<string, string>("Surname", att.Surname ?? string.Empty)
                });

            var httpResponseMessage = await client.PostAsync(endpoint, formContent);
            var responseContent = await httpResponseMessage.Content.ReadAsStringAsync();

            return Ok(responseContent);
        }
        catch (Exception ex)
        {
            string error = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
            att.ErrorMessage = $"The account cannot be updated due to the following error: {error}";
            AppInsights.TrackException(_telemetry, ex, "OnPostProfileAsync");
        }

        return Ok(att);
    }

}
