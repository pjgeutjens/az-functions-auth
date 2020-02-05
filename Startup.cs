using System;
using Link4Vets.JWT.AccessTokens;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(TokenAuthInjection.Startup))]
namespace TokenAuthInjection
{
    /// <summary>
    /// Runs when the Azure Functions host starts.
    /// </summary>
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            // Get the configuration files for the OAuth token issuer
            var issuerToken = Environment.GetEnvironmentVariable("IssuerToken");
            var audience = "https://link4vets-dev.azurewebsites.net";
            var issuer = "https://dev-iexrebq4.eu.auth0.com/";

            // Register the access token provider as a singleton
            builder.Services.AddSingleton<IAccessTokenProvider, AccessTokenProvider>(s => new AccessTokenProvider(audience, issuer));
        }
    }
}
