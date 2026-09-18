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

class Failed
{
    /**
     * The authentication guard name.
     */
    public string $guard;

    /**
     * The user the attempter was trying to authenticate as.
     */
    public ?AuthenticatableInterface $user;

    /**
     * The credentials provided by the attempter.
     */
    public array $credentials;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, ?AuthenticatableInterface $user, array $credentials)
    {
        $this->guard = $guard;
        $this->user = $user;
        $this->credentials = $credentials;
    }
}
