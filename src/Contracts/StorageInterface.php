<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Contracts;

/**
 * Key/value storage backend for the blacklist.
 * Backed by Hyperf's cache drivers in the default implementation.
 */
interface StorageInterface
{
    /**
     * Add an item with a time-to-live (seconds). Returns false if it already exists.
     */
    public function add(string $key, mixed $value, int $ttl): bool;

    /**
     * Whether the key exists in storage.
     */
    public function has(string $key): bool;

    /**
     * Get the stored value (or null).
     */
    public function get(string $key): mixed;

    /**
     * Remove a key. Returns true on success.
     */
    public function destroy(string $key): bool;

    /**
     * Remove all keys. Returns true on success.
     */
    public function flush(): bool;
}
