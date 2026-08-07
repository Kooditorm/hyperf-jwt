<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Contracts;

/**
 * Contract for any user / subject model that can be authenticated via JWT.
 *
 * Mirrors tymon/jwt-auth's JWTSubject — the auth layer uses these two
 * methods to populate the token's `sub` claim and merge model-specific
 * custom claims (e.g. role, permissions).
 */
interface JWTSubject
{
    /**
     * Get the identifier that will be stored in the `sub` claim.
     *
     * Typically the model's primary key.
     */
    public function getJWTIdentifier(): mixed;

    /**
     * Return a key-value array of custom claims to add to the JWT.
     *
     * These are merged with the default registered claims (iat, exp, nbf, ...).
     *
     * @return array<string,mixed>
     */
    public function getJWTCustomClaims(): array;
}
