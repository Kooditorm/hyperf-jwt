<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;

class Expiration extends Claim
{
    use DatetimeTrait;

    protected string $name = 'exp';

    public function validatePayload(): mixed
    {
        if ($this->isPast((int) $this->getValue())) {
            throw new TokenExpiredException('Token has expired');
        }

        return $this->getValue();
    }
}
