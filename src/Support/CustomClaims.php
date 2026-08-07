<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Support;

/**
 * Helper trait for implementing {@see \Kooditorm\Hyperf\Jwt\Contracts\JWTSubject}.
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
