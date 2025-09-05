using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;

namespace woodgrovedemo.Pages
{
    [Authorize]
    public class TokenModel : PageModel
    {
        private readonly IConfiguration _configuration;
        private TelemetryClient _telemetry;
        readonly IAuthorizationHeaderProvider _authorizationHeaderProvider;

        public string IdToken { get; set; } = string.Empty;
        public string IdTokenExpiresIn { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public string AccessTokenError { get; set; } = string.Empty;
        public string DownstreamAccessToken { get; set; } = string.Empty;
        public string DownstreamAccessTokenError { get; set; } = string.Empty;
        public string? ActAs { get; set; } = "";
        public string? AuthScheme { get; set; } = "";

        public TokenModel(IConfiguration configuration, TelemetryClient telemetry, IAuthorizationHeaderProvider authorizationHeaderProvider)
        {
            _configuration = configuration;
            _telemetry = telemetry;
            _authorizationHeaderProvider = authorizationHeaderProvider;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            _telemetry.TrackPageView("Token");

            // Get the act as information
            ActAs = User.Claims.FirstOrDefault(c => c.Type.ToLower() == "act_as")?.Value;

            // Get the act as information
            AuthScheme = User.Claims.FirstOrDefault(c => c.Type == "AuthScheme")?.Value;

            // Read app settings
            string baseUrl = _configuration.GetSection("WoodgroveGroceriesApi:BaseUrl")!.Value!;
            string[] scopes = _configuration.GetSection("WoodgroveGroceriesApi:Scopes")!.Get<string[]>()!;
            string endpoint = _configuration.GetSection("WoodgroveGroceriesApi:Endpoint")!.Value! + "account";

            // Check the scopes application settings
            if (scopes == null)
            {
                AccessTokenError = "The WoodgroveGroceriesApi:Scopes application setting is misconfigured or missing. Use the array format: [\"Account.Payment\", \"Account.Purchases\"]";
                return Page();
            }

            // Check the base URL application settings
            if (string.IsNullOrEmpty(baseUrl))
            {
                AccessTokenError = "The WoodgroveGroceriesApi:BaseUrl application setting is misconfigured or missing. Check out your applications' scope base URL in Microsoft Entra admin center. For example: api://12345678-0000-0000-0000-000000000000";
                return Page();
            }

            // Check the endpoint application settings
            if (string.IsNullOrEmpty(endpoint))
            {
                AccessTokenError = "The WoodgroveGroceriesApi:Endpoint application setting is misconfigured or missing.";
                return Page();
            }

            // Set the scope full URL (temporary workaround should be fix)
            for (int i = 0; i < scopes.Length; i++)
            {
                scopes[i] = $"{baseUrl}/{scopes[i]}";
            }

            try
            {
                this.IdToken = await HttpContext.GetTokenAsync("id_token") ?? "ID token is not available. Please sign-in again.";

                var handler = new JwtSecurityTokenHandler();

                var jsonToken = handler.ReadToken(this.IdToken);
                var diff = (DateTime.UtcNow - jsonToken.ValidTo);
                this.IdTokenExpiresIn = $"The ID token expires in {diff:hh\\:mm\\:ss}";
            }
            catch (System.Exception ex)
            {
                IdTokenExpiresIn = ex.Message;
            }

            try
            {
                // Get an access token to call the "Account" API (the first API in line)
                if (AuthScheme == OpenIdConnectDefaults.AuthenticationScheme)
                {
                    AccessToken = await _authorizationHeaderProvider.CreateAuthorizationHeaderForUserAsync(scopes);
                    string at = await HttpContext.GetTokenAsync("access_token") ?? "Access token is not available. Please sign-in again.";
                }
                else
                {
                    AccessToken = "";
                }
            }
            catch (MicrosoftIdentityWebChallengeUserException ex)
            {
                if (ex.MsalUiRequiredException.ErrorCode == "user_null")
                {
                    AccessTokenError = "The token cache does not contain the token to access the web APIs. To get the access token, sign-out and sign-in again.";
                }
                else
                {
                    AccessTokenError = ex.MsalUiRequiredException.Message;
                }

                return Page();
            }
            catch (System.Exception ex)
            {

                AccessTokenError = ex.Message;

                return Page();
            }


            try
            {
                if (AuthScheme == OpenIdConnectDefaults.AuthenticationScheme)
                {
                    // Use the access token to call the Account API.
                    HttpClient client = new HttpClient();
                    client.DefaultRequestHeaders.Add("Authorization", AccessToken);
                    string jsonString = await client.GetStringAsync(endpoint);

                    // The Account API invokes the downstream "Payment" API. To call the Payment API, the Account API uses
                    // the OAuth2 on-behalf-of flow to exchange the access token to a new one that fits 
                    // the Payment API's audience and scopes (permissions). 
                    // The Account API returns the access token so you can compare the two access tokens.
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    AccountData accountData = JsonSerializer.Deserialize<AccountData>(jsonString, options)!;

                    if (string.IsNullOrEmpty(accountData.Error))
                    {
                        if (accountData.Payment != null)
                        {
                            DownstreamAccessToken = accountData.Payment.AccessTokenToCallThePaymentAPI ?? string.Empty;
                        }
                        else
                        {
                            DownstreamAccessTokenError = "Payment information is missing in the account data.";
                        }
                    }
                    else
                    {
                        DownstreamAccessTokenError = "Woodgrove Groceries account API returned error: " + accountData.Error;
                    }
                }
            }
            catch (System.Exception ex)
            {
                DownstreamAccessTokenError = ex.Message;
            }

            return Page();
        }
    }
}
