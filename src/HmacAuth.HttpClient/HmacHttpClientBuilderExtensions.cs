using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HmacAuth.HttpClient;

public static class HmacHttpClientBuilderExtensions
{
    public static IHttpClientBuilder AddHmacSigningHandler(
        this IHttpClientBuilder builder,
        Action<HmacSigningOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.AddOptions<HmacSigningOptions>(builder.Name).Configure(configure);

        builder.AddHttpMessageHandler(serviceProvider =>
        {
            var optionsMonitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacSigningOptions>>();
            return new HmacSigningHandler(optionsMonitor.Get(builder.Name));
        });

        return builder;
    }
}
