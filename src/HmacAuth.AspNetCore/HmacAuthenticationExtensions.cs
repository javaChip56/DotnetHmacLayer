using HmacAuth.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HmacAuth.AspNetCore;

public static class HmacAuthenticationExtensions
{
    public static AuthenticationBuilder AddHmac(
        this AuthenticationBuilder builder,
        Action<HmacAuthenticationOptions>? configure = null)
    {
        return builder.AddHmac(HmacAuthenticationDefaults.AuthenticationScheme, configure);
    }

    public static AuthenticationBuilder AddHmac(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<HmacAuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);

        return builder.AddScheme<HmacAuthenticationOptions, HmacAuthenticationHandler>(
            authenticationScheme,
            configure ?? (_ => { }));
    }

    public static IServiceCollection AddInMemoryHmacCredentialStore(
        this IServiceCollection services,
        IEnumerable<HmacClientCredentials> credentials)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(credentials);

        services.RemoveAll<IHmacCredentialStore>();
        services.AddSingleton<IHmacCredentialStore>(_ => new InMemoryHmacCredentialStore(credentials));
        return services;
    }

    public static IServiceCollection AddInMemoryHmacNonceStore(
        this IServiceCollection services,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.RemoveAll<IHmacNonceStore>();
        services.AddSingleton<IHmacNonceStore>(_ => new InMemoryHmacNonceStore(timeProvider));
        return services;
    }
}
