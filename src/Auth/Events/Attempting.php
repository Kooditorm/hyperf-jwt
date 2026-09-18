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

class Attempting
{
    /**
     * The authentication guard name.
     */
    public string $guard;

    /**
     * The credentials for the user.
     */
    public array $credentials;

    /**
     * Indicates if the user should be "remembered".
     */
    public bool $remember;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, array $credentials, bool $remember)
    {
        $this->guard = $guard;
        $this->credentials = $credentials;
        $this->remember = $remember;
    }
}
