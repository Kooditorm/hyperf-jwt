<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;

class Expiration extends AbstractClaim
{
    use DatetimeTrait;

    protected string $name = 'exp';

    /**
     * @throws TokenExpiredException
     */
    public function validate(bool $ignoreExpired = false): bool
    {
        if (! $ignoreExpired && $this->isPast($this->getValue())) {
            throw new TokenExpiredException('Token has expired');
        }

        return true;
    }
}
