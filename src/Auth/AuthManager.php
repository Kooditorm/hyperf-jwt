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

use Closure;
use Hyperf\Contract\ConfigInterface;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\GuardInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use InvalidArgumentException;
use Psr\Container\ContainerInterface;

use function Hyperf\Support\make;

class AuthManager extends AuthManagerInterface
{
    use ContextHelpers;

    /**
     * The application instance.
     *
     * @var \Psr\Container\ContainerInterface
     */
    protected $container;

    /**
     * The config instance.
     *
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $config;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config    = make(ConfigInterface::class);
    }
}