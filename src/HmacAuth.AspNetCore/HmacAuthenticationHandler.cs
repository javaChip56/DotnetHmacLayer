using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using HmacAuth.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace HmacAuth.AspNetCore;

public sealed class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
{
    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorizationHeaderValues))
        {
            return AuthenticateResult.NoResult();
        }

        if (!HmacAuthorizationHeaderValue.TryParse(authorizationHeaderValues.ToString(), out var authorizationHeader))
        {
            return AuthenticateResult.Fail("Invalid HMAC authorization header.");
        }

        if (!TryReadHeader(HmacAuthenticationDefaults.TimestampHeaderName, out var timestampValue) ||
            !TryReadHeader(HmacAuthenticationDefaults.NonceHeaderName, out var nonceValue) ||
            !TryReadHeader(HmacAuthenticationDefaults.ContentHashHeaderName, out var contentHashValue))
        {
            return AuthenticateResult.Fail("Missing required HMAC headers.");
        }

        if (!long.TryParse(timestampValue, NumberStyles.None, CultureInfo.InvariantCulture, out var timestampSeconds))
        {
            return AuthenticateResult.Fail("Invalid HMAC timestamp.");
        }

        var requestTimestamp = DateTimeOffset.FromUnixTimeSeconds(timestampSeconds);
        var timeProvider = Options.TimeProvider ?? TimeProvider.System;
        var currentTimestamp = timeProvider.GetUtcNow();

        if ((currentTimestamp - requestTimestamp).Duration() > Options.AllowedClockSkew)
        {
            return AuthenticateResult.Fail("HMAC timestamp is outside the allowed window.");
        }

        if (Options.RequireNonceValidation)
        {
            var nonceStore = Context.RequestServices.GetService<IHmacNonceStore>();
            if (nonceStore is null)
            {
                return AuthenticateResult.Fail("Nonce validation is enabled but no nonce store is registered.");
            }

            var expiresAt = currentTimestamp + Options.AllowedClockSkew;
            var stored = await nonceStore.TryStoreAsync(
                authorizationHeader.ClientId,
                nonceValue,
                expiresAt,
                Context.RequestAborted);

            if (!stored)
            {
                return AuthenticateResult.Fail("HMAC nonce has already been used.");
            }
        }

        var computedContentHash = await ComputeRequestContentHashAsync(Context.RequestAborted);
        if (!HmacSignatureProvider.FixedTimeEquals(contentHashValue, computedContentHash))
        {
            return AuthenticateResult.Fail("HMAC content hash validation failed.");
        }

        var credentialStore = Context.RequestServices.GetService<IHmacCredentialStore>();
        if (credentialStore is null)
        {
            return AuthenticateResult.Fail("No HMAC credential store is registered.");
        }

        var credential = await credentialStore.FindAsync(authorizationHeader.ClientId, Context.RequestAborted);
        if (credential is null)
        {
            return AuthenticateResult.Fail("Unknown HMAC client.");
        }

        var descriptor = new HmacRequestDescriptor(
            authorizationHeader.ClientId,
            Request.Method,
            $"{Request.PathBase}{Request.Path}",
            Request.QueryString.Value,
            timestampValue,
            nonceValue,
            contentHashValue);

        var canonicalRequest = HmacCanonicalRequestBuilder.BuildCanonicalRequest(descriptor);
        var expectedSignature = HmacSignatureProvider.ComputeSignature(canonicalRequest, credential.Secret);

        if (!HmacSignatureProvider.FixedTimeEquals(authorizationHeader.Signature, expectedSignature))
        {
            return AuthenticateResult.Fail("HMAC signature validation failed.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, credential.ClientId),
            new Claim(ClaimTypes.Name, credential.ClientId),
            new Claim(ClaimTypes.AuthenticationMethod, HmacAuthenticationDefaults.AuthenticationScheme),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers[HeaderNames.WWWAuthenticate] = HmacAuthenticationDefaults.AuthenticationScheme;
        return base.HandleChallengeAsync(properties);
    }

    private bool TryReadHeader(string headerName, out string value)
    {
        value = string.Empty;

        return Request.Headers.TryGetValue(headerName, out var headerValues) &&
               !string.IsNullOrWhiteSpace(value = headerValues.ToString());
    }

    private async Task<string> ComputeRequestContentHashAsync(CancellationToken cancellationToken)
    {
        Request.EnableBuffering();

        Request.Body.Position = 0;
        using var memoryStream = new MemoryStream();
        await Request.Body.CopyToAsync(memoryStream, cancellationToken);
        Request.Body.Position = 0;

        return HmacContentHasher.ComputeHashBase64(memoryStream.ToArray());
    }
}
