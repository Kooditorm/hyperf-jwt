<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Blacklist;

use Kooditorm\Hyperf\Jwt\Contracts\StorageInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Payload\Payload;

/**
 * Manages token revocation.
 *
 * A token is blacklisted by its `jti`. A grace period may be configured so
 * that a freshly-invalidated token remains usable for a short window (useful
 * when rotating tokens: the old one must still work while the client picks up
 * the new one).
 */
class Blacklist
{
    protected StorageInterface $storage;

    /**
     * Seconds after invalidation during which the token is still accepted.
     */
    protected int $gracePeriod = 0;

    /**
     * Maximum TTL (seconds) a blacklist entry is kept in storage.
     */
    protected int $storageTtl = 20160;

    /**
     * Whether the blacklist is enabled at all.
     */
    protected bool $enabled = true;

    public function __construct(StorageInterface $storage, int $gracePeriod = 0, int $storageTtl = 20160, bool $enabled = true)
    {
        $this->storage = $storage;
        $this->gracePeriod = $gracePeriod;
        $this->storageTtl = $storageTtl;
        $this->enabled = $enabled;
    }

    /**
     * Add a token (by its jti) to the blacklist.
     *
     * @return bool False when blacklist is disabled or the token has no jti / is already expired.
     */
    public function add(Payload $payload): bool
    {
        if (! $this->enabled) {
            return false;
        }

        if (! $payload->has('jti')) {
            throw new JWTException('A `jti` claim is required to blacklist a token.');
        }

        $jti = (string) $payload->value('jti');
        $exp = $payload->has('exp') ? (int) $payload->value('exp') : null;

        $now = time();

        // The entry lives until the token's own expiry (so it can never be
        // accepted after exp anyway) — but capped by storageTtl.
        if ($exp !== null && $exp > $now) {
            $ttl = min($exp - $now, $this->storageTtl);
        } else {
            $ttl = $this->storageTtl;
        }

        if ($ttl <= 0) {
            return false;
        }

        return $this->storage->add($jti, [
            'valid_until' => $now + $this->gracePeriod,
            'exp' => $exp,
        ], $ttl);
    }

    /**
     * Whether the token is currently blacklisted (and outside its grace period).
     */
    public function has(Payload $payload): bool
    {
        if (! $this->enabled) {
            return false;
        }

        if (! $payload->has('jti')) {
            return false;
        }

        $jti = (string) $payload->value('jti');
        $entry = $this->storage->get($jti);

        if ($entry === null) {
            return false;
        }

        // Grace period: token is still considered valid.
        if (isset($entry['valid_until']) && $entry['valid_until'] > time()) {
            return false;
        }

        return true;
    }

    /**
     * Remove a token from the blacklist (un-revoke).
     */
    public function remove(Payload $payload): bool
    {
        if (! $payload->has('jti')) {
            return false;
        }

        return $this->storage->destroy((string) $payload->value('jti'));
    }

    /**
     * Clear the entire blacklist.
     */
    public function clear(): bool
    {
        return $this->storage->flush();
    }

    public function setGracePeriod(int $gracePeriod): static
    {
        $this->gracePeriod = $gracePeriod;

        return $this;
    }

    public function setStorageTtl(int $storageTtl): static
    {
        $this->storageTtl = $storageTtl;

        return $this;
    }

    public function setEnabled(bool $enabled): static
    {
        $this->enabled = $enabled;

        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getStorage(): StorageInterface
    {
        return $this->storage;
    }
}
