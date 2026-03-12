# HmacAuth

Reusable `.NET 8` HMAC authentication components for service-to-service APIs.

## Projects

- `src/HmacAuth.Core`
  Shared canonicalization, hashing, and signature primitives.
- `src/HmacAuth.AspNetCore`
  ASP.NET Core authentication handler for verifying inbound HMAC requests.
- `src/HmacAuth.HttpClient`
  `DelegatingHandler` for signing outbound `HttpClient` requests.
- `tests/HmacAuth.Tests`
  End-to-end tests covering success, replay rejection, and expired timestamps.

## API B: verify HMAC requests

```csharp
using HmacAuth.AspNetCore;
using HmacAuth.Core;

builder.Services.AddInMemoryHmacCredentialStore(
    [new HmacClientCredentials("client-a", "super-secret-key")]);
builder.Services.AddInMemoryHmacNonceStore();

builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
    .AddHmac(options =>
    {
        options.AllowedClockSkew = TimeSpan.FromMinutes(5);
    });

builder.Services.AddAuthorization();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/secure", () => "ok")
    .RequireAuthorization();
```

## API A: sign outbound requests

```csharp
using HmacAuth.HttpClient;

builder.Services.AddHttpClient("secured-api", client =>
    {
        client.BaseAddress = new Uri("https://api-b.local");
    })
    .AddHmacSigningHandler(options =>
    {
        options.ClientId = "client-a";
        options.Secret = "super-secret-key";
    });
```

## Signed headers

- `Authorization: HMAC {clientId}:{signature}`
- `X-Hmac-Timestamp`
- `X-Hmac-Nonce`
- `X-Hmac-Content-SHA256`

The canonical request currently signs:

1. client id
2. method
3. path
4. normalized query string
5. timestamp
6. nonce
7. content hash
