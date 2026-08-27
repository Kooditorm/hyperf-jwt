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

use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;

class AuthManagerResolved
{
    /**
     * @var AuthManagerInterface
     */
    public $auth;

    /**
     * Create a new event instance.
     */
    public function __construct(AuthManagerInterface $auth)
    {
        $this->auth = $auth;
    }
}