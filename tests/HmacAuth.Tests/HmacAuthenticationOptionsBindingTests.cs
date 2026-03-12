using HmacAuth.AspNetCore;
using HmacAuth.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HmacAuth.Tests;

public sealed class HmacAuthenticationOptionsBindingTests
{
    [Fact]
    public void AddHmac_binds_options_from_configuration()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HmacAuthentication:AllowedClockSkew"] = "00:07:00",
                ["HmacAuthentication:RequireNonceValidation"] = "false",
            })
            .Build();

        var services = new ServiceCollection();

        services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
            .AddHmac(configuration.GetSection("HmacAuthentication"));

        using var serviceProvider = services.BuildServiceProvider();
        var optionsMonitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var options = optionsMonitor.Get(HmacAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal(TimeSpan.FromMinutes(7), options.AllowedClockSkew);
        Assert.False(options.RequireNonceValidation);
    }
}
