
namespace woodgrovedemo.Models;
public class UserMoreInfo
{
    public string ErrorMessage { get; set; } = "";

    /* User attributes*/
    public string Identities { get; set; } = "";
    public string LastSignInDateTime { get; set; } = "";
    public string LastSignInRequestId { get; set; } = "";
    public string PhoneNumber { get; set; } = "";
    public string EmailMfa { get; set; } = "";
    public string SingInEmail { get; set; } = "";
    public string signInEmail { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string IssuerTemp { get; set; } = "";
    public string mail { get; set; } = "";
    public string upn { get; set; } = "";
    public string? ObjectId { get; set; } = "";
    public bool AccountEnabled { get; set; } = true;
    public string signintype { get; set; } = "";
}