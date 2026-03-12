using System.Collections.Concurrent;

namespace HmacAuth.AspNetCore;

public sealed class InMemoryHmacNonceStore : IHmacNonceStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public InMemoryHmacNonceStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ValueTask<bool> TryStoreAsync(
        string clientId,
        string nonce,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        var key = $"{clientId}:{nonce}";
        var now = _timeProvider.GetUtcNow();

        while (true)
        {
            if (_entries.TryGetValue(key, out var existingExpiry))
            {
                if (existingExpiry > now)
                {
                    return ValueTask.FromResult(false);
                }

                _entries.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, existingExpiry));
                continue;
            }

            if (_entries.TryAdd(key, expiresAt))
            {
                return ValueTask.FromResult(true);
            }
        }
    }
}
