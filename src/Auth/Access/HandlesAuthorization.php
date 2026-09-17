<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Access;

trait HandlesAuthorization
{
    /**
     * Create a new access response.
     *
     * @param mixed $code
     */
    protected function allow(?string $message = null, mixed $code = null): Response
    {
        return Response::allow($message, $code);
    }

    /**
     * Create a new denied access response.
     *
     * @param mixed $code
     */
    protected function deny(?string $message = null, mixed $code = null): Response
    {
        return Response::deny($message, $code);
    }
}
