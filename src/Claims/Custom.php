<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

/**
 * A user-defined claim with no built-in validation rule.
 */
class Custom extends AbstractClaim
{
    /**
     * @param string $name  The custom claim name
     * @param mixed  $value The custom claim value
     */
    public function __construct(string $name, mixed $value = null)
    {
        parent::__construct($value);
        $this->name = $name;
    }

    public function validate(mixed $value): bool
    {
        // Custom claims are not validated by default.
        return true;
    }
}
