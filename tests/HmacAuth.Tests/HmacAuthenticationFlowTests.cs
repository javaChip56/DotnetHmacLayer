using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using HmacAuth.AspNetCore;
using HmacAuth.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace HmacAuth.Tests;

public sealed class HmacAuthenticationFlowTests
{
    [Fact]
    public async Task Signed_post_request_is_authenticated()
    {
        var now = new DateTimeOffset(2026, 3, 12, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new FixedTimeProvider(now);

        await using var app = await CreateApplicationAsync(timeProvider);
        using var client = CreateSignedClient(app, timeProvider, () => "nonce-post-1");

        using var response = await client.PostAsync(
            "/secure?z=2&a=1",
            new StringContent("{\"message\":\"hello\"}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("client-a", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Reused_nonce_is_rejected()
    {
        var now = new DateTimeOffset(2026, 3, 12, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new FixedTimeProvider(now);

        await using var app = await CreateApplicationAsync(timeProvider);
        using var client = CreateSignedClient(app, timeProvider, () => "nonce-replay");

        using var firstResponse = await client.GetAsync("/secure");
        using var secondResponse = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
    }

    [Fact]
    public async Task Expired_timestamp_is_rejected()
    {
        var requestTime = new DateTimeOffset(2026, 3, 12, 12, 0, 0, TimeSpan.Zero);
        var serverTime = requestTime.AddMinutes(10);

        await using var app = await CreateApplicationAsync(new FixedTimeProvider(serverTime));
        using var client = CreateSignedClient(app, new FixedTimeProvider(requestTime), () => "nonce-expired");

        using var response = await client.GetAsync("/secure");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<WebApplication> CreateApplicationAsync(TimeProvider timeProvider)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddInMemoryHmacCredentialStore(
            [new HmacClientCredentials("client-a", "super-secret-key")]);
        builder.Services.AddInMemoryHmacNonceStore(timeProvider);
        builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
            .AddHmac(options =>
            {
                options.TimeProvider = timeProvider;
                options.AllowedClockSkew = TimeSpan.FromMinutes(5);
            });
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapMethods("/secure", ["GET", "POST"], (ClaimsPrincipal user) => user.Identity?.Name ?? "unknown")
            .RequireAuthorization(new AuthorizeAttribute
            {
                AuthenticationSchemes = HmacAuthenticationDefaults.AuthenticationScheme,
            });

        await app.StartAsync();
        return app;
    }

    private static System.Net.Http.HttpClient CreateSignedClient(
        WebApplication app,
        TimeProvider timeProvider,
        Func<string> nonceFactory)
    {
        var signingHandler = new HmacAuth.HttpClient.HmacSigningHandler(new HmacAuth.HttpClient.HmacSigningOptions
        {
            ClientId = "client-a",
            Secret = "super-secret-key",
            TimeProvider = timeProvider,
            NonceFactory = nonceFactory,
        });
        signingHandler.InnerHandler = app.GetTestServer().CreateHandler();

        return new System.Net.Http.HttpClient(signingHandler)
        {
            BaseAddress = new Uri("http://localhost"),
        };
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
