using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Link4Vets.JWT.AccessTokens;
using System.Security.Claims;

namespace Link4Vets.JWT
{
    public class ValidateJwt
    {
        private readonly IAccessTokenProvider _tokenProvider;

        public ValidateJwt(IAccessTokenProvider tokenProvider)
        {
            _tokenProvider = tokenProvider;
        }

        [FunctionName("ValidateJwt")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var result = await _tokenProvider.ValidateToken(req);

            if (result.Status == AccessTokenStatus.Valid && result.Principal.Identity.IsAuthenticated)
            {
                log.LogInformation($"auth {result.Principal.Identity.IsAuthenticated}.");
                return new OkResult();
            }
            else
            {
                return new UnauthorizedResult();
            }
        }
    }
}
