<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Validators;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;

class TokenValidator extends Validator
{
    public function check($value): string
    {
        return $this->validateStructure($value);
    }

    protected function validateStructure(string $token): string
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new TokenInvalidException('Malformed token');
        }

        return $token;
    }
}
