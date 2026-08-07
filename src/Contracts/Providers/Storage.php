<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts\Providers;

interface Storage
{
    /**
     * Add an item to the storage with a TTL in minutes.
     */
    public function add(string $key, mixed $value, int $minutes): void;

    /**
     * Add an item to the storage indefinitely.
     */
    public function forever(string $key, mixed $value): void;

    /**
     * Get an item from the storage.
     */
    public function get(string $key): mixed;

    /**
     * Remove an item from the storage.
     */
    public function destroy(string $key): bool;

    /**
     * Remove all items from the storage.
     */
    public function flush(): void;
}
