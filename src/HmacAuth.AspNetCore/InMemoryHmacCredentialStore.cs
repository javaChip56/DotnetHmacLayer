using HmacAuth.Core;

namespace HmacAuth.AspNetCore;

public sealed class InMemoryHmacCredentialStore : IHmacCredentialStore
{
    private readonly IReadOnlyDictionary<string, HmacClientCredentials> _credentials;

    public InMemoryHmacCredentialStore(IEnumerable<HmacClientCredentials> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        _credentials = credentials.ToDictionary(static credential => credential.ClientId, StringComparer.Ordinal);
    }

    public ValueTask<HmacClientCredentials?> FindAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        _credentials.TryGetValue(clientId, out var credential);
        return ValueTask.FromResult(credential);
    }
}
