// using JWTAuth_Validation.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuth_Validation.Middleware
{
    public class JWTMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        // private readonly IUserService _userService;

        public JWTMiddleware(RequestDelegate next, IConfiguration configuration/* , IUserService userService */)
        {
            _next = next;
            _configuration = configuration;
            // _userService = userService;
        }

        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                attachAccountToContext(context, token);

            await _next(context);
        }

        private void attachAccountToContext(HttpContext context, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var Key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _configuration["JWT:Issuer"],
                    ValidAudience = _configuration["JWT:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Key)
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    // ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                Console.WriteLine(ObjectDumper.Dump(validatedToken));

                var jwtToken = (JwtSecurityToken)validatedToken;
                var accountId = jwtToken.Claims.First(x => x.Type == "unique_name").Value;

                // attach account to context on successful jwt validation
                // context.Items["User"] = _userService.GetUserDetails();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Token Validation Failed!\n");
                // do nothing if jwt validation fails
                // account is not attached to context so request won't have access to secure routes
            }
        }
    }
}