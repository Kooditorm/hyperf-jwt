<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Stringable;
use TypeError;

/**
 * Immutable value object wrapping a JWT compact-serialisation string.
 *
 * Mirrors tymon/jwt-auth's Token class — keeps the raw string safe behind a
 * typed interface and prevents accidental double-encoding.
 */
class Token implements Stringable
{
    protected string $value;

    public function __construct(string $token)
    {
        $this->value = $token;
    }

    /**
     * Create a Token from a string or another Token instance.
     */
    public static function from(Token|string $token): self
    {
        return $token instanceof self ? $token : new self($token);
    }

    /**
     * Get the raw token string.
     */
    public function get(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * Split the token into its [header, payload, signature] segments.
     *
     * @return array{0:string,1:string,2:string}
     *
     * @throws TypeError When the token is not a well-formed 3-segment JWT.
     */
    public function segments(): array
    {
        $parts = explode('.', $this->value);

        if (count($parts) !== 3) {
            throw new TypeError('A JWT must consist of exactly three segments separated by dots.');
        }

        return [$parts[0], $parts[1], $parts[2]];
    }
}
