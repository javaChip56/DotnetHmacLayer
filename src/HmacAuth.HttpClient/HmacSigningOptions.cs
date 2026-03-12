namespace HmacAuth.HttpClient;

public sealed class HmacSigningOptions
{
    public string ClientId { get; set; } = string.Empty;

    public string Secret { get; set; } = string.Empty;

    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    public Func<string>? NonceFactory { get; set; }
}
