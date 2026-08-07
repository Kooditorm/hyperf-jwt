<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Contracts;

/**
 * Signs a JWT header.payload segment and verifies an existing signature.
 */
interface SignerInterface
{
    /**
     * The JWT algorithm name, e.g. `HS256`, `RS256`, `ES384`.
     */
    public function getAlgorithm(): string;

    /**
     * Sign the given payload (already-base64url(header).base64url(payload)).
     */
    public function sign(string $payload): string;

    /**
     * Verify that the expected signature matches the payload.
     */
    public function verify(string $expected, string $payload): bool;

    /**
     * Whether this signer relies on asymmetric keys.
     */
    public function isAsymmetric(): bool;
}
