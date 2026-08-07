<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Blacklist;

use Psr\SimpleCache\CacheInterface;
use HyperfExt\Jwt\Contracts\StorageInterface;

/**
 * Blacklist storage backed by a PSR-16 cache (Hyperf cache driver).
 *
 * NOTE: `flush()` calls `CacheInterface::clear()`, which clears the entire
 * cache namespace of the underlying driver. It is strongly recommended to
 * give the blacklist its own dedicated cache driver / prefix so that flushing
 * does not affect unrelated application caches.
 */
class BlacklistStorage implements StorageInterface
{
    public function __construct(
        protected CacheInterface $cache,
        protected string $prefix = 'jwt:blacklist:'
    ) {
    }

    public function add(string $key, mixed $value, int $ttl): bool
    {
        $key = $this->prefix . $key;

        if ($this->cache->has($key)) {
            return false;
        }

        return $this->cache->set($key, $value, $ttl);
    }

    public function has(string $key): bool
    {
        return $this->cache->has($this->prefix . $key);
    }

    public function get(string $key): mixed
    {
        return $this->cache->get($this->prefix . $key);
    }

    public function destroy(string $key): bool
    {
        return $this->cache->delete($this->prefix . $key);
    }

    public function flush(): bool
    {
        return $this->cache->clear();
    }

    public function getCache(): CacheInterface
    {
        return $this->cache;
    }
}
