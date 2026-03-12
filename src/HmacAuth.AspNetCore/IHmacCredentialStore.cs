using HmacAuth.Core;

namespace HmacAuth.AspNetCore;

public interface IHmacCredentialStore
{
    ValueTask<HmacClientCredentials?> FindAsync(string clientId, CancellationToken cancellationToken = default);
}
