<?php

declare(strict_types=1);

namespace HyperfExt\Jwt;

use HyperfExt\Jwt\Claims\Factory as ClaimFactory;
use HyperfExt\Jwt\Payload\Payload;

/**
 * Builds {@see Payload} instances by merging default registered claims with
 * user-supplied custom claims.
 *
 * This is the HyperfExt equivalent of tymon/jwt-auth's PayloadFactory — it
 * provides a fluent, chainable API for constructing payloads independently
 * of the encode/decode pipeline.
 *
 * Typical usage:
 *
 *     $payload = $factory->sub(123)->customClaims(['role' => 'admin'])->make();
 */
class PayloadFactory
{
    /**
     * Default registered-claim configuration from the scene.
     *
     * @var array{iss?:string|null,aud?:mixed,exp?:int,nbf?:int,jti?:bool}
     */
    protected array $claimConfig;

    /**
     * Runtime override TTL (seconds). When non-null, overrides the config TTL.
     */
    protected ?int $ttl = null;

    /**
     * Custom claims to merge into every payload built by this instance.
     *
     * @var array<string,mixed>
     */
    protected array $customClaims = [];

    public function __construct(
        protected ClaimFactory $claimFactory
    ) {
        $this->claimConfig = [];
    }

    /**
     * Set the default registered-claim configuration (from the scene).
     *
     * @param array $config
     */
    public function setClaimConfig(array $config): static
    {
        $this->claimConfig = $config;

        return $this;
    }

    /**
     * Merge custom claims into the factory (chainable).
     *
     * @param array<string,mixed> $claims
     */
    public function customClaims(array $claims): static
    {
        $this->customClaims = array_merge($this->customClaims, $claims);

        return $this;
    }

    /**
     * Clear all accumulated custom claims.
     */
    public function clearClaims(): static
    {
        $this->customClaims = [];

        return $this;
    }

    /**
     * Override the TTL (expiration seconds from now) for subsequent builds.
     */
    public function setTTL(int $ttl): static
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the effective TTL (override or config default).
     */
    public function getTTL(): int
    {
        return $this->ttl ?? (int) ($this->claimConfig['exp'] ?? 3600);
    }

    /**
     * Set the subject (sub) claim.
     */
    public function sub(mixed $subject): static
    {
        $this->customClaims['sub'] = $subject;

        return $this;
    }

    /**
     * Set the audience (aud) claim.
     */
    public function aud(mixed $audience): static
    {
        $this->customClaims['aud'] = $audience;

        return $this;
    }

    /**
     * Set the issuer (iss) claim.
     */
    public function iss(string $issuer): static
    {
        $this->customClaims['iss'] = $issuer;

        return $this;
    }

    /**
     * Build the final Payload from defaults + accumulated custom claims.
     */
    public function make(array $customClaims = []): Payload
    {
        // Merge runtime custom claims with per-call claims.
        $merged = array_merge($this->customClaims, $customClaims);

        // If TTL was overridden, inject it as the exp claim config.
        $effectiveConfig = $this->claimConfig;
        if ($this->ttl !== null) {
            $effectiveConfig['exp'] = $this->ttl;
        }

        // Temporarily sync config to the underlying claim factory.
        $this->claimFactory->setClaimConfig($effectiveConfig);

        $claims = $this->claimFactory->build($merged);

        return new Payload($claims);
    }

    /**
     * Build a Payload from an explicit claim-set array (no defaults applied).
     *
     * Useful for decoding — converts raw decoded claims into typed Payload.
     *
     * @param array<string,mixed> $claims
     */
    public function makeFromRaw(array $claims): Payload
    {
        $typed = [];
        foreach ($claims as $name => $value) {
            $typed[$name] = $this->claimFactory->make((string) $name, $value);
        }

        return new Payload($typed);
    }

    public function getClaimFactory(): ClaimFactory
    {
        return $this->claimFactory;
    }
}
