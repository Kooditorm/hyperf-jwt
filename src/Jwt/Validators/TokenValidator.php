<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Validators;

use Kooditorm\Hyperf\Jwt\Contracts\TokenValidatorInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JwtException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;

class TokenValidator extends TokenValidatorInterface
{
    /**
     * Check the structure of the token.
     */
    public function check(string $value): string
    {
        $this->validateStructure($value);
        return $value;
    }

    /**
     * Helper function to return a boolean.
     */
    public function isValid(string $value): bool
    {
        try {
            $this->check($value);
        } catch (JwtException $e) {
            return false;
        }

        return true;
    }

    /**
     * @throws TokenInvalidException
     */
    protected function validateStructure(string $token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 or implode('.', $parts) !== $token) {
            throw new TokenInvalidException('Malformed token');
        }

        return $this;
    }
}