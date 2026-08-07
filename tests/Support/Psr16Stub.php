<?php

declare(strict_types=1);

namespace Psr\SimpleCache;

use DateInterval;

/**
 * Minimal PSR-16 CacheInterface stub for running the test suite without the
 * psr/simple-cache Composer package. Real apps use Composer's autoloader.
 */
if (! interface_exists(CacheInterface::class)) {
    interface CacheInterface
    {
        public function get(string $key, mixed $default = null): mixed;

        public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool;

        public function delete(string $key): bool;

        public function clear(): bool;

        public function getMultiple(iterable $keys, mixed $default = null): iterable;

        public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool;

        public function deleteMultiple(iterable $keys): bool;

        public function has(string $key): bool;
    }
}
