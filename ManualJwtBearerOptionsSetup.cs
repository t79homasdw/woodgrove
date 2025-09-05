using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

public class JwtBearerSettings
{
    public string Authority { get; set; }
    public string Policy { get; set; }
    public string[] ValidIssuers { get; set; }
    public string[] ValidAudiences { get; set; }
}

public class ManualJwtBearerOptionsSetup : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly JwtBearerSettings _jwtSettings;
    public ManualJwtBearerOptionsSetup(IConfiguration configuration)
    {
        _jwtSettings = configuration.GetSection("JwtBearer").Get<JwtBearerSettings>();
    }
    public void Configure(string name, JwtBearerOptions options) => Configure(options);
    public void Configure(JwtBearerOptions options)
    {
        var metadataAddress = $"{_jwtSettings.Authority}/v2.0/.well-known/openid-configuration?p={_jwtSettings.Policy}";
        
        var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
             metadataAddress,
             new OpenIdConnectConfigurationRetriever(),
             new HttpDocumentRetriever { RequireHttps = true });

        var config = configManager.GetConfigurationAsync(CancellationToken.None).GetAwaiter().GetResult();

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuers = _jwtSettings.ValidIssuers,
            ValidAudiences = _jwtSettings.ValidAudiences,
            IssuerSigningKeys = config.SigningKeys,
            ValidateIssuerSigningKey = true, // Disables signature validation if false
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidateAudience = true,
            NameClaimType = "oid",
            RequireSignedTokens = true
        };
        options.TokenValidationParameters.ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 };
    }
}
