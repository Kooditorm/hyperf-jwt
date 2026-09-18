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
use InvalidArgumentException;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\GuardInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Auth\Events\AuthManagerResolved;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function Hyperf\Support\make;

class AuthManager implements AuthManagerInterface
{
    use ContextHelpers;

    protected ConfigInterface $config;

    protected EventDispatcherInterface $eventDispatcher;

    /**
     * Create a new Auth manager instance.
     */
    public function __construct(protected readonly ContainerInterface $container)
    {
        $this->config = $container->get(ConfigInterface::class);
        $this->eventDispatcher = $container->get(EventDispatcherInterface::class);

        $this->resolveUsersUsing($this->getUserResolverClosure());
        $this->eventDispatcher->dispatch(new AuthManagerResolved($this));
    }

    /**
     * Attempt to get the guard from the local cache.
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
    public function setDefaultDriver(string $name): void
    {
        $this->config->set('auth.default.guard', $name);
    }

    /**
     * Get the user resolver callback.
     */
    public function userResolver(): Closure
    {
        return $this->getContext('userResolver');
    }

    /**
     * Set the callback to be used to resolve users.
     */
    public function resolveUsersUsing(Closure $userResolver): static
    {
        $this->setContext('userResolver', $userResolver);

        return $this;
    }

    /**
     * Create the user provider implementation for the driver.
     *
     * @throws InvalidArgumentException
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
     * @throws InvalidArgumentException
     */
    protected function resolve(string $name): GuardInterface
    {
        $config = $this->getConfig($name);

        if (empty($config['driver'])) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }

        $provider = $this->createUserProvider($config['provider'] ?? null);
        $options = $config['options'] ?? [];

        return make($config['driver'], compact('provider', 'name', 'options'));
    }

    protected function getUserResolverClosure(): Closure
    {
        return function (?string $guard = null) {
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
