<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;
use Kooditorm\Hyperf\Jwt\Support\Utils;

class IssuedAt extends Claim
{
    use DatetimeTrait;

    protected string $name = 'iat';

    public function validateRefresh(int $refreshTTL): mixed
    {
        if ($refreshTTL !== 0 && Utils::timestamp((int) $this->getValue())->addMinutes($refreshTTL)->isPast()) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed');
        }

        return $this->getValue();
    }
}
