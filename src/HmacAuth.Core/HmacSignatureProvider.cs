using System.Security.Cryptography;
using System.Text;

namespace HmacAuth.Core;

public static class HmacSignatureProvider
{
    public static string ComputeSignature(string canonicalRequest, string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalRequest);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var requestBytes = Encoding.UTF8.GetBytes(canonicalRequest);

        using var hmac = new HMACSHA256(secretBytes);
        return Convert.ToBase64String(hmac.ComputeHash(requestBytes));
    }

    public static bool FixedTimeEquals(string left, string right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(left),
            Encoding.UTF8.GetBytes(right));
    }
}
