namespace HmacAuth.AspNetCore;

public interface IHmacNonceStore
{
    ValueTask<bool> TryStoreAsync(
        string clientId,
        string nonce,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
