using JWTIssuer.Services;

namespace JWTIssuer.Extensions;

public static class DependenciesExtensions
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddSingleton<TokenService>();
        return services;
    }
}