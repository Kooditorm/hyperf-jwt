<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts;

/**
 * Abstraction over the low-level JWT encoding and decoding engine.
 *
 * This mirrors tymon/jwt-auth's JWTProvider interface — it decouples the
 * cryptographic / serialisation layer from the business logic so that
 * alternative engines (lcobucci, Namshi, etc.) can be swapped in.
 */
interface JWTProvider
{
    /**
     * Encode a claim-set into a signed compact-serialisation JWT string.
     *
     * @param array<string,mixed> $payload
     */
    public function encode(array $payload): string;

    /**
     * Decode a JWT string into its claim-set array.
     *
     * Only the signature is verified; claim-level validation (exp, nbf, iss,
     * etc.) is the caller's responsibility.
     *
     * @return array<string,mixed>
     */
    public function decode(string $token): array;
}
