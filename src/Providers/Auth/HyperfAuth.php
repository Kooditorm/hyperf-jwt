<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Providers\Auth;

use Hyperf\Context\Context;
use Hyperf\Database\Model\Model;
use Psr\Container\ContainerInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth as AuthContract;

/**
 * Default Hyperf auth provider.
 *
 * This provider uses a configurable user model to authenticate users.
 * It stores the authenticated user in the coroutine context.
 */
class HyperfAuth implements AuthContract
{
    protected ContainerInterface $container;

    protected string $userModel;

    protected ?string $userContextKey = 'kooditorm.jwt.user';

    public function __construct(ContainerInterface $container, string $userModel = '')
    {
        $this->container = $container;
        $this->userModel = $userModel;
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
            fn ($key) => $key !== 'password',
            ARRAY_FILTER_USE_KEY
        );

        /** @var Model $model */
        $model = new $this->userModel();
        $user = $model->newQuery()->where($queryCredentials)->first();

        if ($user && $password !== null) {
            // Verify password using password_verify
            $hash = $user->getAuthPassword() ?? $user->password ?? null;
            if (! password_verify($password, $hash)) {
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
