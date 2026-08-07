<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Claims;

/**
 * `jti` - JWT ID: provides a unique identifier for the JWT.
 *
 * Used primarily for blacklist keying / revocation.
 */
class JwtId extends AbstractClaim
{
    protected string $name = 'jti';

    public function validate(mixed $value): bool
    {
        return $value === $this->getValue();
    }
}
