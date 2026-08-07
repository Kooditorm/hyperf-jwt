<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

/**
 * `exp` - Expiration Time: the time after which the JWT MUST NOT be accepted.
 */
class Expiration extends AbstractClaim
{
    protected string $name = 'exp';

    public function validate(mixed $value): bool
    {
        if (! is_numeric($value)) {
            return false;
        }

        // Allow a leeway window so clock skew does not cause premature expiry.
        return (int) $value >= (time() - $this->leeway);
    }
}
