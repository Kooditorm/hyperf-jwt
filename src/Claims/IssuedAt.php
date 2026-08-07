<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Claims;

/**
 * `iat` - Issued At: the time at which the JWT was issued.
 *
 * A token may not claim to have been issued in the future.
 */
class IssuedAt extends AbstractClaim
{
    protected string $name = 'iat';

    public function validate(mixed $value): bool
    {
        if (! is_numeric($value)) {
            return false;
        }

        return (int) $value <= (time() + $this->leeway);
    }
}
