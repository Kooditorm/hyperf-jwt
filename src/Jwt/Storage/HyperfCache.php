<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Storage;

use Kooditorm\Hyperf\Jwt\Contracts\StorageInterface;
use Psr\SimpleCache\CacheInterface;

class HyperfCache implements StorageInterface
{
    public function __construct(
        protected readonly CacheInterface $cache,
        protected readonly string $tag
    ) {
    }

    public function add(string $key, mixed $value, int $ttl): void
    {
        $this->cache->set($this->resolveKey($key), $value, $ttl);
    }

    public function forever(string $key, mixed $value): void
    {
        $this->cache->set($this->resolveKey($key), $value);
    }

    /**
     * @return mixed
     */
    public function get(string $key)
    {
        return $this->cache->get($this->resolveKey($key));
    }

    public function destroy(string $key): bool
    {
        return $this->cache->delete($this->resolveKey($key));
    }

    public function flush(): void
    {
        method_exists($cache = $this->cache, 'clearPrefix')
            ? $cache->clearPrefix($this->tag)
            : $cache->clear();
    }

    protected function cache(): CacheInterface
    {
        return $this->cache;
    }

    protected function resolveKey(string $key): string
    {
        return $this->tag . '.' . $key;
    }
}
