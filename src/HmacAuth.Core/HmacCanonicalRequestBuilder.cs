namespace HmacAuth.Core;

public static class HmacCanonicalRequestBuilder
{
    public static string BuildCanonicalRequest(HmacRequestDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        return string.Join(
            '\n',
            descriptor.ClientId,
            NormalizeMethod(descriptor.HttpMethod),
            NormalizePath(descriptor.Path),
            NormalizeQueryString(descriptor.QueryString),
            descriptor.Timestamp,
            descriptor.Nonce,
            descriptor.ContentHash);
    }

    public static string NormalizeQueryString(string? rawQueryString)
    {
        if (string.IsNullOrWhiteSpace(rawQueryString))
        {
            return string.Empty;
        }

        var segments = rawQueryString.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(ParseSegment)
            .OrderBy(static segment => segment.Key, StringComparer.Ordinal)
            .ThenBy(static segment => segment.Value, StringComparer.Ordinal)
            .Select(static segment => segment.ToString());

        return string.Join("&", segments);
    }

    public static string NormalizePath(string? rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return "/";
        }

        var path = rawPath.Trim();
        return path.StartsWith('/') ? path : $"/{path}";
    }

    public static string NormalizeMethod(string? method)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        return method.ToUpperInvariant();
    }

    private static QuerySegment ParseSegment(string segment)
    {
        var separatorIndex = segment.IndexOf('=');
        if (separatorIndex < 0)
        {
            return new QuerySegment(segment, string.Empty);
        }

        return new QuerySegment(
            segment[..separatorIndex],
            segment[(separatorIndex + 1)..]);
    }

    private readonly record struct QuerySegment(string Key, string Value)
    {
        public override string ToString() => Value.Length == 0 ? Key : $"{Key}={Value}";
    }
}
