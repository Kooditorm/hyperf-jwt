<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Providers\Auth;

use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Database\Model\Model;
use Psr\Container\ContainerInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth as AuthContract;
use Kooditorm\Hyperf\Jwt\Contracts\Auth\Factory as FactoryContract;
use InvalidArgumentException;

/**
 * Default Hyperf auth provider.
 *
 * This provider uses a configurable user model to authenticate users.
 * It stores the authenticated user in the coroutine context.
 */
class HyperfAuth implements AuthContract, FactoryContract
{
    protected ContainerInterface $container;

    protected string $userModel;

    /**
     * The array of created "drivers".
     *
     * @var array
     */
    protected $guards = [];

    /**
     * The user resolver shared by various services.
     *
     * Determines the default user for Gate, Request, and the Authenticatable contract.
     *
     * @var \Closure
     */
    protected $userResolver;

    protected ConfigInterface $config;

    protected ?string $userContextKey = 'kooditorm.jwt.user';


    public function __construct(ContainerInterface $container, ConfigInterface $config = [])
    {
        $this->container = $container;
        $this->config = $config;
        $this->userModel = $config->get('jwt.user_model', '');
        $this->userResolver = fn($guard = null) => $this->guard($guard)->user();
    }

    public function guard($name = null)
    {
        $name = $name ?: $this->getDefaultDriver();

        return $this->guards[$name] ?? $this->guards[$name] = $this->resolve($name);
    }

    protected function resolve($name)
    {
        $config = $this->getConfig($name);

        if (is_null($config)) {
            throw new InvalidArgumentException("Auth guard [$name] is not defined.");
        }
    }

    /**
     * Get the default authentication driver name.
     *
     * @return string
     */
    public function getDefaultDriver()
    {
        return $this->config->get('jwt.auth.defaults.guard');
    }

    /**
     * Get the guard configuration.
     *
     * @param  string  $name
     * @return array
     */
    protected function getConfig($name)
    {
        return $this->config->get('jwt.auth.guards.' . $name);
    }

    public function createUserProvider($provider = null)
    {
        if (is_null($config = $this->getProviderConfiguration($provider))) {
            return;
        }
        print_r($config);
        return $this;
    }

    /**
     * Get the user provider configuration.
     *
     * @param  string|null  $provider
     * @return array|null
     */
    protected function getProviderConfiguration($provider)
    {
        if ($provider = $provider ?: $this->getDefaultUserProvider()) {
            return $this->config->get('jwt.auth.providers.' . $provider);
        }
    }

    /**
     * Get the default user provider name.
     *
     * @return string
     */
    public function getDefaultUserProvider()
    {
        return $this->config->get('jwt.auth.defaults.provider');
    }

    public function byCredentials(array $credentials): bool
    {
        if (empty($this->userModel)) {
            return false;
        }

        // Remove password from credentials for the query
        $password = $credentials['password'] ?? null;
        $queryCredentials = array_filter(
            $credentials,
            fn($key) => $key !== 'password',
            ARRAY_FILTER_USE_KEY
        );

        /** @var Model $model */
        $model = new $this->userModel();
        $user = $model->newQuery()->where($queryCredentials)->first();

        if ($user && $password !== null) {
            // Verify password using password_verify
            $hash = $user->getAuthPassword() ?? $user->password ?? null;
            if (!password_verify($password, $hash)) {
                return false;
            }
        }

        if ($user) {
            Context::set($this->userContextKey, $user);
            return true;
        }

        return false;
    }

    public function byId(mixed $id): bool
    {
        if (empty($this->userModel)) {
            return false;
        }

        /** @var Model $model */
        $model = new $this->userModel();
        $user = $model->newQuery()->find($id);

        if ($user) {
            Context::set($this->userContextKey, $user);
            return true;
        }

        return false;
    }

    public function user(): mixed
    {
        return Context::get($this->userContextKey);
    }

    public function setUserModel(string $userModel): static
    {
        $this->userModel = $userModel;

        return $this;
    }
}
