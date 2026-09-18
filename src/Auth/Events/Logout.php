<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Events;

use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;

class Logout
{
    /**
     * The authentication guard name.
     */
    public string $guard;

    /**
     * The authenticated user.
     */
    public AuthenticatableInterface $user;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, AuthenticatableInterface $user)
    {
        $this->guard = $guard;
        $this->user = $user;
    }
}
