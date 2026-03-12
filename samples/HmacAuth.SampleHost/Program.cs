using System.Security.Claims;
using HmacAuth.AspNetCore;
using HmacAuth.Core;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

var sampleCredential = builder.Configuration.GetSection("SampleCredential").Get<SampleCredentialOptions>()
    ?? throw new InvalidOperationException("SampleCredential configuration is missing.");

if (string.IsNullOrWhiteSpace(sampleCredential.ClientId) || string.IsNullOrWhiteSpace(sampleCredential.Secret))
{
    throw new InvalidOperationException("SampleCredential must define both ClientId and Secret.");
}

builder.Services.AddInMemoryHmacCredentialStore(
    [new HmacClientCredentials(sampleCredential.ClientId, sampleCredential.Secret)]);
builder.Services.AddInMemoryHmacNonceStore();
builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
    .AddHmac(builder.Configuration.GetSection("HmacAuthentication"));
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Json(new
{
    name = "HmacAuth.SampleHost",
    publicEndpoint = "/public/ping",
    secureEndpoints = new[] { "/secure/whoami", "/secure/echo" },
    expectedClientId = sampleCredential.ClientId,
}));

app.MapGet("/public/ping", () => Results.Json(new
{
    message = "Sample host is running.",
    utcNow = DateTimeOffset.UtcNow,
}));

var secureGroup = app.MapGroup("/secure")
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = HmacAuthenticationDefaults.AuthenticationScheme,
    });

secureGroup.MapGet("/whoami", (ClaimsPrincipal user) => Results.Json(new
{
    message = "HMAC authentication succeeded.",
    clientId = user.Identity?.Name,
}));

secureGroup.MapPost("/echo", async (ClaimsPrincipal user, HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();

    return Results.Json(new
    {
        message = "Signed POST request accepted.",
        clientId = user.Identity?.Name,
        request.ContentType,
        body,
    });
});

app.Run();

internal sealed class SampleCredentialOptions
{
    public string ClientId { get; init; } = string.Empty;

    public string Secret { get; init; } = string.Empty;
}
