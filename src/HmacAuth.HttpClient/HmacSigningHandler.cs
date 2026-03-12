using System.Globalization;
using System.Net.Http.Headers;
using HmacAuth.Core;

namespace HmacAuth.HttpClient;

public sealed class HmacSigningHandler : DelegatingHandler
{
    private readonly HmacSigningOptions _options;

    public HmacSigningHandler(HmacSigningOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.RequestUri);

        if (string.IsNullOrWhiteSpace(_options.ClientId) || string.IsNullOrWhiteSpace(_options.Secret))
        {
            throw new InvalidOperationException("ClientId and Secret must be configured for HMAC signing.");
        }

        var timestamp = _options.TimeProvider.GetUtcNow()
            .ToUnixTimeSeconds()
            .ToString(CultureInfo.InvariantCulture);

        var nonce = _options.NonceFactory?.Invoke();
        if (string.IsNullOrWhiteSpace(nonce))
        {
            nonce = Guid.NewGuid().ToString("N");
        }

        var contentHash = await ComputeContentHashAsync(request.Content, cancellationToken);
        var descriptor = new HmacRequestDescriptor(
            _options.ClientId,
            request.Method.Method,
            request.RequestUri.AbsolutePath,
            request.RequestUri.Query,
            timestamp,
            nonce,
            contentHash);

        var canonicalRequest = HmacCanonicalRequestBuilder.BuildCanonicalRequest(descriptor);
        var signature = HmacSignatureProvider.ComputeSignature(canonicalRequest, _options.Secret);

        request.Headers.Authorization = new AuthenticationHeaderValue(
            HmacAuthenticationDefaults.AuthenticationScheme,
            $"{_options.ClientId}:{signature}");

        request.Headers.Remove(HmacAuthenticationDefaults.TimestampHeaderName);
        request.Headers.Remove(HmacAuthenticationDefaults.NonceHeaderName);
        request.Headers.Remove(HmacAuthenticationDefaults.ContentHashHeaderName);

        request.Headers.TryAddWithoutValidation(HmacAuthenticationDefaults.TimestampHeaderName, timestamp);
        request.Headers.TryAddWithoutValidation(HmacAuthenticationDefaults.NonceHeaderName, nonce);
        request.Headers.TryAddWithoutValidation(HmacAuthenticationDefaults.ContentHashHeaderName, contentHash);

        return await base.SendAsync(request, cancellationToken);
    }

    private static async Task<string> ComputeContentHashAsync(HttpContent? content, CancellationToken cancellationToken)
    {
        if (content is null)
        {
            return HmacContentHasher.ComputeEmptyHashBase64();
        }

        var bytes = await content.ReadAsByteArrayAsync(cancellationToken);
        return HmacContentHasher.ComputeHashBase64(bytes);
    }
}
