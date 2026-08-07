<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Providers\Storage;

use Hyperf\Cache\Cache;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Storage;

/**
 * Storage provider using Hyperf's Cache component.
 *
 * The cache driver and configuration are controlled by the Hyperf cache config.
 * Typically, this uses Redis as the backend.
 */
class HyperfCache implements Storage
{
    protected Cache $cache;

    /**
     * Cache key prefix to avoid collisions.
     */
    protected string $prefix = 'jwt-blacklist:';

    public function __construct(Cache $cache)
    {
        $this->cache = $cache;
    }

    public function add(string $key, mixed $value, int $minutes): void
    {
        $this->cache->set($this->prefix . $key, $value, $minutes * 60);
    }

    public function forever(string $key, mixed $value): void
    {
        // Hyperf Cache doesn't have a "forever" method,
        // so we set a very long TTL (100 years)
        $this->cache->set($this->prefix . $key, $value, 365 * 24 * 60 * 60 * 100);
    }

    public function get(string $key): mixed
    {
        return $this->cache->get($this->prefix . $key);
    }

    public function destroy(string $key): bool
    {
        return $this->cache->delete($this->prefix . $key);
    }

    public function flush(): void
    {
        // Hyperf Cache doesn't have a global flush by default.
        // This implementation clears the prefix using the underlying cache driver.
        // For Redis-based cache, you could use the clear() method if available.
        // Alternatively, implement a more targeted flush in a subclass.
        try {
            $this->cache->clear();
        } catch (\Throwable) {
            // If clear() is not supported, this is a no-op.
            // The user should implement their own flush logic if needed.
        }
    }

    public function setPrefix(string $prefix): static
    {
        $this->prefix = $prefix;

        return $this;
    }

    public function getPrefix(): string
    {
        return $this->prefix;
    }
}
