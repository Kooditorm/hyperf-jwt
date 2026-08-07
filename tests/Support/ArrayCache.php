<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Tests\Support;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/**
 * A trivial in-memory PSR-16 cache for tests. Supports TTL in seconds.
 */
class ArrayCache implements CacheInterface
{
    /** @var array<string,array{value:mixed,expires:?int}> */
    protected array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (! $this->has($key)) {
            return $default;
        }

        return $this->data[$key]['value'];
    }

    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $expires = null;
        if (is_int($ttl) && $ttl > 0) {
            $expires = time() + $ttl;
        }

        $this->data[$key] = ['value' => $value, 'expires' => $expires];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->data = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        if (! isset($this->data[$key])) {
            return false;
        }

        $expires = $this->data[$key]['expires'];
        if ($expires !== null && $expires < time()) {
            unset($this->data[$key]);

            return false;
        }

        return true;
    }
}
