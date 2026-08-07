<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Hyperf\Stringable\Str;

class JwtId extends Claim
{
    protected string $name = 'jti';

    public function validateCreate(mixed $value): mixed
    {
        if ($value === null || $value === '') {
            return Str::random(16);
        }

        return $value;
    }
}
