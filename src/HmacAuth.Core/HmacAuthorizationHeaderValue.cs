using System.Net.Http.Headers;

namespace HmacAuth.Core;

public readonly record struct HmacAuthorizationHeaderValue(string ClientId, string Signature)
{
    public static string Format(string clientId, string signature)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(signature);

        return $"{HmacAuthenticationDefaults.AuthenticationScheme} {clientId}:{signature}";
    }

    public static bool TryParse(string? headerValue, out HmacAuthorizationHeaderValue value)
    {
        value = default;

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        if (!AuthenticationHeaderValue.TryParse(headerValue, out var parsed))
        {
            return false;
        }

        if (!string.Equals(
                parsed.Scheme,
                HmacAuthenticationDefaults.AuthenticationScheme,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return false;
        }

        var separatorIndex = parsed.Parameter.IndexOf(':');
        if (separatorIndex <= 0 || separatorIndex == parsed.Parameter.Length - 1)
        {
            return false;
        }

        value = new HmacAuthorizationHeaderValue(
            parsed.Parameter[..separatorIndex],
            parsed.Parameter[(separatorIndex + 1)..]);

        return true;
    }
}
