namespace HmacAuth.Core;

public static class HmacAuthenticationDefaults
{
    public const string AuthenticationScheme = "HMAC";
    public const string TimestampHeaderName = "X-Hmac-Timestamp";
    public const string NonceHeaderName = "X-Hmac-Nonce";
    public const string ContentHashHeaderName = "X-Hmac-Content-SHA256";
}
