<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;

class NotBefore extends Claim
{
    use DatetimeTrait;

    protected string $name = 'nbf';

    public function validatePayload(): mixed
    {
        if ($this->isFuture((int) $this->getValue())) {
            throw new TokenInvalidException('Token not yet valid');
        }

        return $this->getValue();
    }
}
