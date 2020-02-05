namespace Link4Vets.JWT.AccessTokens
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Validates a incoming request and extracts any <see cref="ClaimsPrincipal"/> contained within the bearer token.
    /// </summary>
    public class AccessTokenProvider : IAccessTokenProvider
    {
        private const string AUTH_HEADER_NAME = "Authorization";
        private const string BEARER_PREFIX = "Bearer ";
        private readonly HttpDocumentRetriever documentRetriever;
        private readonly string _issuer;
        private readonly string _audience;
        private List<SecurityKey> _keys = new List<SecurityKey>();


        public AccessTokenProvider(string audience, string issuer)
        {
            _issuer = issuer;
            _audience = audience;

            this.documentRetriever = new HttpDocumentRetriever();
        }

        public async Task<List<SecurityKey>> GetKeys()
        {
            if (this._keys.Count > 0) {
                return this._keys;
            }
            else 
            {
                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{this._issuer}.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                this.documentRetriever
                );

                var openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);

                var signingKeys = openIdConfig.SigningKeys.ToList();

                this._keys = signingKeys;

                return signingKeys;
            }
            
        }

        public async Task<AccessTokenResult> ValidateToken(HttpRequest request)
        {
            try
            {
                // Get the token from the header
                if (request != null &&
                    request.Headers.ContainsKey(AUTH_HEADER_NAME) &&
                    request.Headers[AUTH_HEADER_NAME].ToString().StartsWith(BEARER_PREFIX))
                {
                    var token = request.Headers[AUTH_HEADER_NAME].ToString().Substring(BEARER_PREFIX.Length);

                    // Create the parameters
                    var tokenParams = new TokenValidationParameters()
                    {
                        RequireSignedTokens = true,
                        ValidAudience = _audience,
                        ValidateAudience = true,
                        ValidIssuer = _issuer,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidateLifetime = true,
                        IssuerSigningKeys = await this.GetKeys()
                    };

                    // Validate the token
                    var handler = new JwtSecurityTokenHandler();
                    var result = handler.ValidateToken(token, tokenParams, out var securityToken);
                    return AccessTokenResult.Success(result);
                }
                else
                {
                    return AccessTokenResult.NoToken();
                }
            }
            catch (SecurityTokenExpiredException)
            {
                return AccessTokenResult.Expired();
            }
            catch (Exception ex)
            {
                return AccessTokenResult.Error(ex);
            }
        }
    }
}
