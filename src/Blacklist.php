<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Contracts\Providers\Storage;
use Kooditorm\Hyperf\Jwt\Support\Utils;

class Blacklist
{
    protected Storage $storage;

    protected int $gracePeriod = 0;

    protected int $refreshTTL = 20160;

    protected string $key = 'jti';

    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     */
    public function add(Payload $payload): bool
    {
        // If there is no exp claim, add the jwt to the blacklist indefinitely
        if (! $payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        // If we have already added this token to the blacklist
        if (! empty($this->storage->get($this->getKey($payload)))) {
            return true;
        }

        $this->storage->add(
            $this->getKey($payload),
            ['valid_until' => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );

        return true;
    }

    /**
     * Get the number of minutes until the token expiry (including refresh TTL).
     */
    protected function getMinutesUntilExpired(Payload $payload): int
    {
        $exp = Utils::timestamp((int) $payload['exp']);

        // Calculate the refresh expiry from the issued-at time
        $refreshExpiry = Utils::timestamp((int) $payload['iat'])->addMinutes($this->refreshTTL);

        // Get the latter of the two expiration dates, plus 1 minute buffer
        $expiration = $exp->max($refreshExpiry)->addMinute();

        $minutes = method_exists($expiration, 'diffInRealMinutes')
            ? $expiration->diffInRealMinutes()
            : (method_exists($expiration, 'diffInUTCMinutes')
                ? $expiration->diffInUTCMinutes()
                : $expiration->diffInMinutes());

        return (int) ceil(abs($minutes));
    }

    /**
     * Add the token to the blacklist indefinitely.
     */
    public function addForever(Payload $payload): bool
    {
        $this->storage->forever($this->getKey($payload), 'forever');

        return true;
    }

    /**
     * Determine whether the token has been blacklisted.
     */
    public function has(Payload $payload): bool
    {
        $val = $this->storage->get($this->getKey($payload));

        // Exit early if the token was blacklisted forever
        if ($val === 'forever') {
            return true;
        }

        // Check whether the expiry + grace period has passed
        return ! empty($val) && ! Utils::isFuture((int) $val['valid_until']);
    }

    /**
     * Remove the token from the blacklist.
     */
    public function remove(Payload $payload): bool
    {
        return $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     */
    public function clear(): bool
    {
        $this->storage->flush();

        return true;
    }

    protected function getGraceTimestamp(): int
    {
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    public function setGracePeriod(int $gracePeriod): static
    {
        $this->gracePeriod = (int) $gracePeriod;

        return $this;
    }

    public function getGracePeriod(): int
    {
        return $this->gracePeriod;
    }

    public function getKey(Payload $payload): mixed
    {
        return $payload($this->key);
    }

    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    public function setRefreshTTL(int $ttl): static
    {
        $this->refreshTTL = (int) $ttl;

        return $this;
    }

    public function getRefreshTTL(): int
    {
        return $this->refreshTTL;
    }
}
