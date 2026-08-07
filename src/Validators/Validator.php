<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Validators;

use Kooditorm\Hyperf\Jwt\Contracts\Validator as ValidatorContract;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Support\RefreshFlow;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    public function isValid(mixed $value): bool
    {
        try {
            $this->check($value);
        } catch (JWTException) {
            return false;
        }

        return true;
    }
}
