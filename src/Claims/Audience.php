<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Claims;

/**
 * `aud` - Audience: identifies the recipients that the JWT is intended for.
 *
 * During validation, the token's audience is compared against the configured
 * audience. If the configured value is an array, membership is checked.
 */
class Audience extends AbstractClaim
{
    protected string $name = 'aud';

    public function validate(mixed $value): bool
    {
        $expected = $this->getValue();

        if ($expected === null) {
            return true;
        }

        // Token audience may be a string or an array of strings (per RFC 7519).
        if (is_array($expected)) {
            $tokenAudiences = is_array($value) ? $value : [$value];

            return ! empty(array_intersect($expected, $tokenAudiences));
        }

        if (is_array($value)) {
            return in_array($expected, $value, true);
        }

        return $value === $expected;
    }
}
