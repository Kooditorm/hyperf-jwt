<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

/**
 * `nbf` - Not Before: the time before which the JWT MUST NOT be accepted.
 */
class NotBefore extends AbstractClaim
{
    protected string $name = 'nbf';

    public function validate(mixed $value): bool
    {
        if (! is_numeric($value)) {
            return false;
        }

        return (int) $value <= (time() + $this->leeway);
    }
}
