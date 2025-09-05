using System.Dynamic;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Azure.Identity;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using woodgrovedemo.Helpers;
using woodgrovedemo.Models;

namespace woodgrovedemo.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class UserMoreInfoController : ControllerBase
{
    // Dependency injection
    private readonly IConfiguration _configuration;
    private TelemetryClient _telemetry;

    public UserMoreInfoController(IConfiguration configuration, TelemetryClient telemetry)
    {
        _configuration = configuration;
        _telemetry = telemetry;
    }

    public async Task<IActionResult> GetAsync()
    {
        UserMoreInfo userMoreInfo = new UserMoreInfo();

        // Get the user unique identifier
        string? userObjectId = User.GetObjectId();

        var graphClient = MsalAccessTokenHandler.GetGraphClient(_configuration);

        try
        {
            User? profile = await graphClient.Users[userObjectId].GetAsync(requestConfiguration =>
            {
                requestConfiguration.QueryParameters.Select = new string[] { 
                    "Id", 
                    "identities", 
                    "signInActivity", 
                    "userprincipalname",
                    "mail",
                    "issuer",
                    "UserType"
                };
            });


            // Get the sign-in activity
            if (profile != null && profile.SignInActivity != null)
            {
                userMoreInfo.LastSignInDateTime = profile!.SignInActivity!.LastSignInDateTime!.ToString()!;
                userMoreInfo.LastSignInRequestId = profile!.SignInActivity.LastSignInRequestId!;
            }
            else
            {
                userMoreInfo.LastSignInDateTime = "Data is not yet available.";
                userMoreInfo.LastSignInRequestId = userMoreInfo.LastSignInDateTime;
            }


            // Get the user identities
            foreach (var identity in profile!.Identities!)
            {               
                if (identity.SignInType == "federated")
                {
                userMoreInfo.Issuer = identity.Issuer!;
                userMoreInfo.upn = profile.UserPrincipalName!;
                userMoreInfo.signintype = identity.SignInType;
                userMoreInfo.IssuerTemp = userMoreInfo.signintype + " " + identity.Issuer!;

                    if (identity.Issuer?.Contains("mail") ?? true)
                    {
                        userMoreInfo.SingInEmail = identity.IssuerAssignedId!;
                        userMoreInfo.signInEmail = identity.IssuerAssignedId!;
                    }
                    else
                    {
                        userMoreInfo.SingInEmail = "Unknown";
                        userMoreInfo.signInEmail = "Unknown";
                    }

                    userMoreInfo.Identities =
                    (userMoreInfo.signintype != null ? $"<li><b>Sign-in type</b>: {userMoreInfo.signintype}</li>" : "") +
                    (userMoreInfo.Issuer != null ? $"<li><b>Issuer</b>: {userMoreInfo.Issuer}</li>" : "") +
                    (userMoreInfo.SingInEmail != null ? $"<li><b>Username</b>: {userMoreInfo.SingInEmail}</ui>" : "") +
                    (userMoreInfo.IssuerTemp != null ? $"<li><b>Issuer Type</b>: {userMoreInfo.IssuerTemp}</li>" : "") +
                    (userMoreInfo.upn != null ? $"<li><b>UserPrincipalName</b>: {userMoreInfo.upn}</li>" : "");
                }
                else
                {
                    if (identity.SignInType == "userPrincipalName" && !(userMoreInfo.IssuerTemp?.Contains("mail") ?? false))
                    {
                        userMoreInfo.Issuer = identity.Issuer!;
                        userMoreInfo.signintype = identity.SignInType;
                        
                        // Get the sign-in email address
                        if (profile.Mail != null) 
                        { 
                            userMoreInfo.SingInEmail = profile.Mail!;
                            userMoreInfo.signInEmail = profile.Mail!;
                            userMoreInfo.upn = profile.UserPrincipalName!;
                        }
                        else
                        {
                            userMoreInfo.SingInEmail = profile.UserPrincipalName!;
                            userMoreInfo.signInEmail = profile.UserPrincipalName!;
                            userMoreInfo.upn = profile.UserPrincipalName!;
                            userMoreInfo.IssuerTemp = profile.UserType!;
                        }
                        
                        userMoreInfo.Identities =
                        (userMoreInfo.signintype != null ? $"<li><b>Sign-in type</b>: {userMoreInfo.signintype}</li>" : "") +
                        (userMoreInfo.Issuer != null ? $"<li><b>Entra Issuer</b>: {userMoreInfo.Issuer}</li>" : "") +
                        (userMoreInfo.SingInEmail != null ? $"<li><b>Username</b>: {userMoreInfo.SingInEmail}</ui>" : "") +
                        (userMoreInfo.IssuerTemp != null ? $"<li><b>Issuer Type</b>: {userMoreInfo.IssuerTemp}</li>" : "") +
                        (userMoreInfo.upn != null ? $"<li><b>UserPrincipalName</b>: {userMoreInfo.upn}</li>" : "");
                    }
                    
                }
            }
        }
        catch (ODataError odataError)
        {
            userMoreInfo.ErrorMessage = $"Can't read the profile due to the following error: {odataError.Error!.Message} Error code: {odataError.Error.Code}";
            AppInsights.TrackException(_telemetry, odataError, "GetRolesAndGroupsAsync");
        }
        catch (Exception ex)
        {
            string error = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
            userMoreInfo.ErrorMessage = $"Can't read the profile due to the following error: {error}";
            AppInsights.TrackException(_telemetry, ex, "GetRolesAndGroupsAsync");
        }

        bool StepUpFulfilled = User.Claims.Any(c => c.Type == "acrs" && c.Value == "c1");
        try
        {
            var result = await graphClient.Users[userObjectId].Authentication.Methods.GetAsync();

            if (result != null && result.Value != null)
            {
                foreach (var method in result.Value)
                {
                    if (method.OdataType == "#microsoft.graph.phoneAuthenticationMethod")
                    {
                        userMoreInfo.PhoneNumber = ((PhoneAuthenticationMethod)method).PhoneNumber ?? string.Empty;
                    }
                    else if (method.OdataType == "#microsoft.graph.emailAuthenticationMethod")
                    {
                        userMoreInfo.EmailMfa = ((EmailAuthenticationMethod)method).EmailAddress ?? string.Empty;
                    }
                }
            }

            if (string.IsNullOrEmpty(userMoreInfo.PhoneNumber))
                userMoreInfo.PhoneNumber = "";

            if (string.IsNullOrEmpty(userMoreInfo.EmailMfa))
                userMoreInfo.EmailMfa = "";
        }
        catch (ODataError odataError)
        {
            userMoreInfo.ErrorMessage = $"Can't read the authentication methods due to the following error: {odataError.Error!.Message} Error code: {odataError.Error.Code}";
            AppInsights.TrackException(_telemetry, odataError, "GetAuthenticationMethodsAsync");
        }
        catch (Exception ex)
        {
            string error = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
            userMoreInfo.ErrorMessage = $"Can't read the authentication methods due to the following error: {error}";
            AppInsights.TrackException(_telemetry, ex, "GetAuthenticationMethodsAsync");
        }
        return Ok(userMoreInfo);
    }
}