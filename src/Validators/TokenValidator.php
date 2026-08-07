<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Validators;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use Kooditorm\Hyperf\Jwt\Token;

/**
 * Validates the structural format of a JWT token string.
 *
 * Mirrors tymon/jwt-auth's TokenValidator — performs a lightweight format
 * check before the token is handed to the JWTProvider for cryptographic
 * verification. This allows early rejection of obviously malformed input.
 */
class TokenValidator
{
    /**
     * Validate that the token string looks like a compact-serialisation JWT.
     *
     * @throws TokenInvalidException
     */
    public function check(Token|string $token): Token
    {
        $token = Token::from($token);
        $value = $token->get();

        if ($value === '') {
            throw new TokenInvalidException('Token is empty.');
        }

        $segments = explode('.', $value);

        if (count($segments) !== 3) {
            throw new TokenInvalidException('Wrong number of token segments; expected 3.');
        }

        foreach ($segments as $i => $segment) {
            if ($segment === '') {
                throw new TokenInvalidException(sprintf('Token segment #%d is empty.', $i));
            }
        }

        // base64url characters only: [A-Za-z0-9_-]
        foreach ($segments as $segment) {
            if (! preg_match('/^[A-Za-z0-9_-]+$/', $segment)) {
                throw new TokenInvalidException('Token contains invalid base64url characters.');
            }
        }

        return $token;
    }
}
