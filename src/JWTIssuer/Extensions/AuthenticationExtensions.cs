using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace JWTIssuer.Extensions;

public static class AuthenticationExtensions
{
    public static WebApplicationBuilder AddCustomJwtAuthentication(this WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.MapInboundClaims = false;
            
            var rsa = RSA.Create();
            rsa.ImportFromPem(builder.Configuration["Jwt:PublicKey"]!);
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true
            };
        });
        return builder;
    }
}