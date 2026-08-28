<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Guards;

use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Macroable\Macroable;
use Kooditorm\Hyperf\Auth\Contracts\StatelessGuardInterface;
use Kooditorm\Hyperf\Auth\GuardHelpers;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Hyperf\Contract\ContainerInterface;
use Kooditorm\Hyperf\Jwt\Jwt;

class JwtGuard implements StatelessGuardInterface
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }


    /**
     * The name of the Guard. Typically "jwt".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name;

    /**
     * The user we last attempted to retrieve.
     *
     * @var AuthenticatableInterface
     */
    protected $lastAttempted;

    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var Jwt
     */
    protected $jwt;

    /**
     * @var RequestInterface
     */
    protected $request;
}