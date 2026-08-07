<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Exceptions;

use InvalidArgumentException;

class InvalidClaimException extends InvalidArgumentException
{
    public function __construct(private object $claim)
    {
        $name = method_exists($claim, 'getName') ? $claim->getName() : 'unknown';

        parent::__construct('Invalid value provided for claim [' . $name . ']');
    }

    public function getClaim(): object
    {
        return $this->claim;
    }
}
