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
        $this->resolveUsersUsing($this->getUserResolverClosure());
    }

    /**
     * Attempt to get the guard from the local cache.
     *
     * @return \Kooditorm\Hyperf\Auth\Contracts\GuardInterface|\Kooditorm\Hyperf\Auth\Contracts\StatefulGuardInterface
     */
    public function guard(?string $name = null): GuardInterface
    {
        $name = $name ?: $this->getDefaultDriver();
        $id = 'guards.' . $name;
        return $this->getContext($id) ?: $this->setContext($id, $this->resolve($name));
    }

    /**
     * Get the default authentication driver name.
     */
    public function getDefaultDriver(): string
    {
        return $this->config->get('auth.default.guard');
    }

    /**
     * Set the default guard driver the factory should serve.
     */
    public function shouldUse(string $name): void
    {
        $name = $name ?: $this->getDefaultDriver();

        $this->setDefaultDriver($name);

        $this->resolveUsersUsing($this->getUserResolverClosure());
    }

    /**
     * Set the default authentication driver name.
     */
    public function setDefaultDriver(string $name)
    {
        $this->config->set('auth.default.guard', $name);
    }

    /**
     * Get the user resolver callback.
     *
     * @return \Closure
     */
    public function userResolver()
    {
        return $this->getContext('userResolver');
    }

    /**
     * Set the callback to be used to resolve users.
     *
     * @return $this
     */
    public function resolveUsersUsing(Closure $userResolver)
    {
        $this->setContext('userResolver', $userResolver);

        return $this;
    }

    /**
     * Create the user provider implementation for the driver.
     *
     * @throws \InvalidArgumentException
     */
    public function createUserProvider(?string $provider = null): ?UserProviderInterface
    {
        $provider = $provider ?: $this->config->get('auth.default.provider', null);

        $config = $this->config->get('auth.providers.' . $provider);

        if (is_null($config)) {
            throw new InvalidArgumentException(
                "Authentication user provider [{$provider}] must be defined."
            );
        }

        $driverClass = $config['driver'] ?? null;
        if (empty($driverClass)) {
            throw new InvalidArgumentException(
                'Authentication user provider driver must be defined.'
            );
        }

        return make($driverClass, ['options' => $config['options'] ?? []]);
    }


    /**
     * Resolve the given guard.
     *
     *@throws \InvalidArgumentException
     * @return \Kooditorm\Hyperf\Auth\Contracts\GuardInterface|\HyperfExtension\Auth\Contracts\StatefulGuardInterface
     */
    protected function resolve(string $name)
    {
        $config = $this->getConfig($name);

        if (empty($config)) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }

        if (empty($config['driver'])) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }

        $provider = $this->createUserProvider($config['provider'] ?? null);
        $options = $config['options'] ?? [];

        return make($config['driver'], compact('provider', 'name', 'options'));
    }


    protected function getUserResolverClosure()
    {
        return function ($guard = null) {
            if (! empty($guard)) {
                return $this->guard($guard)->user();
            }
            $guards = array_keys($this->config->get('auth.guards'));
            foreach ($guards as $guard) {
                if (! empty($user = $this->guard($guard)->user())) {
                    return $user;
                }
            }
            return null;
        };
    }


    /**
     * Get the guard configuration.
     */
    protected function getConfig(string $name): array
    {
        return $this->config->get("auth.guards.{$name}");
    }

}