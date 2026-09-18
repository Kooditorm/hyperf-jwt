<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth;

use Hyperf\Context\Context;

trait ContextHelpers
{
    public function setContext(string $id, mixed $value): mixed
    {
        Context::set(static::class . '.' . $id, $value);

        return $value;
    }

    public function getContext(string $id, mixed $default = null, ?int $coroutineId = null): mixed
    {
        return Context::get(static::class . '.' . $id, $default, $coroutineId);
    }
}
