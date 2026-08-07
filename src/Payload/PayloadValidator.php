<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Payload;

use Kooditorm\Hyperf\Jwt\Claims\Audience;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenNotYetValidException;

/**
 * Validates the claims of a decoded payload against configured expectations
 * and time-based constraints.
 */
class PayloadValidator
{
    /**
     * Expected claim values from the active scene config (iss, aud, ...).
     *
     * @var array<string,mixed>
     */
    protected array $expectedClaims = [];

    protected int $leeway = 0;

    /**
     * @param array<string,mixed> $expectedClaims
     */
    public function setExpectedClaims(array $expectedClaims): static
    {
        $this->expectedClaims = $expectedClaims;

        return $this;
    }

    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Run all checks. Returns the payload on success, throws on failure.
     *
     * @throws TokenExpiredException
     * @throws TokenNotYetValidException
     * @throws TokenInvalidException
     */
    public function validate(Payload $payload): Payload
    {
        $this->validateExpiration($payload);
        $this->validateNotBefore($payload);
        $this->validateIssuedAt($payload);
        $this->validateIssuer($payload);
        $this->validateAudience($payload);

        return $payload;
    }

    protected function validateExpiration(Payload $payload): void
    {
        if (! $payload->has('exp')) {
            return;
        }

        $exp = $payload->value('exp');
        if (! is_numeric($exp)) {
            throw new TokenInvalidException('The `exp` claim must be numeric.');
        }

        if ((int) $exp < (time() - $this->leeway)) {
            throw new TokenExpiredException('Token has expired.');
        }
    }

    protected function validateNotBefore(Payload $payload): void
    {
        if (! $payload->has('nbf')) {
            return;
        }

        $nbf = $payload->value('nbf');
        if (! is_numeric($nbf)) {
            throw new TokenInvalidException('The `nbf` claim must be numeric.');
        }

        if ((int) $nbf > (time() + $this->leeway)) {
            throw new TokenNotYetValidException('Token is not yet valid.');
        }
    }

    protected function validateIssuedAt(Payload $payload): void
    {
        if (! $payload->has('iat')) {
            return;
        }

        $iat = $payload->value('iat');
        if (! is_numeric($iat)) {
            throw new TokenInvalidException('The `iat` claim must be numeric.');
        }

        if ((int) $iat > (time() + $this->leeway)) {
            throw new TokenInvalidException('Token was issued in the future.');
        }
    }

    protected function validateIssuer(Payload $payload): void
    {
        $expected = $this->expectedClaims['iss'] ?? null;
        if ($expected === null) {
            return;
        }

        if (! $payload->has('iss') || $payload->value('iss') !== $expected) {
            throw new TokenInvalidException('Token issuer does not match.');
        }
    }

    protected function validateAudience(Payload $payload): void
    {
        $expected = $this->expectedClaims['aud'] ?? null;
        if ($expected === null) {
            return;
        }

        $tokenAudience = $payload->has('aud') ? $payload->value('aud') : null;

        $audienceClaim = (new Audience($expected))->withLeeway($this->leeway);

        if (! $audienceClaim->validate($tokenAudience)) {
            throw new TokenInvalidException('Token audience does not match.');
        }
    }
}
