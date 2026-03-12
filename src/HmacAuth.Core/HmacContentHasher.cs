using System.Security.Cryptography;

namespace HmacAuth.Core;

public static class HmacContentHasher
{
    public static string ComputeHashBase64(ReadOnlySpan<byte> content)
    {
        return Convert.ToBase64String(SHA256.HashData(content));
    }

    public static string ComputeHashBase64(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return ComputeHashBase64(content.AsSpan());
    }

    public static string ComputeHashBase64(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return ComputeHashBase64(System.Text.Encoding.UTF8.GetBytes(content));
    }

    public static string ComputeEmptyHashBase64()
    {
        return ComputeHashBase64([]);
    }
}
