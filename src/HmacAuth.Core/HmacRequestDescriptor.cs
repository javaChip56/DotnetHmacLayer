namespace HmacAuth.Core;

public sealed record HmacRequestDescriptor(
    string ClientId,
    string HttpMethod,
    string Path,
    string? QueryString,
    string Timestamp,
    string Nonce,
    string ContentHash);
