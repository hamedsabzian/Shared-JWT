using System.Security.Claims;
using System.Security.Cryptography;
using JWTIssuer.Extensions;
using JWTIssuer.Models;
using JWTIssuer.Services;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.AddCustomJwtAuthentication();
builder.Services.AddAuthorization();

builder.Services.AddServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/auth/login", Results<Ok<LoginResponseModel>, UnauthorizedHttpResult> (LoginRequestModel input, TokenService tokenService) =>
    {
        // Validate the user credentials
        if (input.UserName != "foo" || input.Password != "bar")
        {
            return TypedResults.Unauthorized();
        }

        // Pass the user real information to generate the JWT token
        return TypedResults.Ok(new LoginResponseModel(tokenService.GenerateJtw(Guid.NewGuid().ToString(), input.UserName)));
    })
    .WithName("login")
    .WithOpenApi();

app.MapGet("/user-info", (ClaimsPrincipal user) => new UserInfoResponseModel(user.Identity!.Name!))
    .WithName("user-info")
    .WithOpenApi()
    .RequireAuthorization();

app.MapGet("/.well-known/openid-configuration", (IConfiguration configuration) => Results.Ok(new
{
    issuer = configuration["Jwt:Issuer"], jwks_uri = $"{configuration["Host"]}/.well-known/openid-configuration/jwks"
}));

app.MapGet("/.well-known/openid-configuration/jwks", (IConfiguration configuration) =>
{
    RSA rsa = RSA.Create();
    rsa.ImportFromPem(configuration["Jwt:PublicKey"]);
    RSAParameters keysInformation = rsa.ExportParameters(false);
    return Results.Ok(new
    {
        keys = new[]
        {
            new
            {
                kty = "RSA",
                use = "sig",
                kid = configuration["Jwt:KeyId"],
                n = Base64UrlEncoder.Encode(keysInformation.Modulus),
                e = Base64UrlEncoder.Encode(keysInformation.Exponent),
            },
        },
    });
});

app.Run();