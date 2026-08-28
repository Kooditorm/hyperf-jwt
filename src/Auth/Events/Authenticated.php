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

class Authenticated
{
    /**
     * The authentication guard name.
     *
     * @var string
     */
    public $guard;

    /**
     * The authenticated user.
     *
     * @var AuthenticatableInterface
     */
    public $user;

    /**
     * Create a new event instance.
     */
    public function __construct(string $guard, AuthenticatableInterface $user)
    {
        $this->user = $user;
        $this->guard = $guard;
    }
}