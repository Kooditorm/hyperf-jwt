<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Support;

/**
 * Helper trait for implementing {@see \HyperfExt\Jwt\Contracts\JWTSubject}.
 *
 * Provides a default (empty) `getJWTCustomClaims` so models only need to
 * implement `getJWTIdentifier`.
 *
 * Mirrors tymon/jwt-auth's CustomClaims trait.
 */
trait CustomClaims
{
    /**
     * @return array<string,mixed>
     */
    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
