<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\UserProviders;

use Hyperf\Contract\Arrayable;
use Hyperf\Database\Model\Model;
use Hyperf\Stringable\Str;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Hash\Contract\DriverInterface;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;

class ModelUserProvider implements UserProviderInterface
{
    /**
     * The hasher implementation.
     */
    protected DriverInterface $hasher;

    /**
     * The Eloquent user model class name.
     */
    protected string $model;

    /**
     * Create a new database user provider.
     */
    public function __construct(HashInterface $hash, array $options)
    {
        $this->model = $options['model'] ?? null;
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof DriverInterface
            ? $hasher
            : $hash->getDriver($hasher);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @return null|AuthenticatableInterface|Model
     */
    public function retrieveById(mixed $identifier): ?AuthenticatableInterface
    {
        $model = $this->createModel();

        return $this->newModelQuery($model)
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @return null|AuthenticatableInterface|Model
     */
    public function retrieveByToken(mixed $identifier, string $token): ?AuthenticatableInterface
    {
        $model = $this->createModel();

        $retrievedModel = $this->newModelQuery($model)->where(
            $model->getAuthIdentifierName(),
            $identifier
        )->first();

        if (! $retrievedModel) {
            return null;
        }

        $rememberToken = $retrievedModel->getRememberToken();

        return $rememberToken && hash_equals($rememberToken, $token) ? $retrievedModel : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param AuthenticatableInterface|Model $user
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);

        $timestamps = $user->timestamps;

        $user->timestamps = false;

        $user->save();

        $user->timestamps = $timestamps;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @return null|AuthenticatableInterface|Model
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (
            empty($credentials)
            || (count($credentials) === 1 && Str::contains($this->firstCredentialKey($credentials), 'password'))
        ) {
            return null;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.
        $query = $this->newModelQuery();

        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool
    {
        return $this->hasher->check($credentials['password'], $user->getAuthPassword());
    }

    /**
     * Create a new instance of the model.
     *
     * @return AuthenticatableInterface|Model
     */
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');

        return new $class();
    }

    /**
     * Gets the hasher implementation.
     */
    public function getHashInterface(): HashInterface
    {
        return $this->hasher;
    }

    /**
     * Sets the hasher implementation.
     */
    public function setHashInterface(HashInterface $hasher): static
    {
        $this->hasher = $hasher;

        return $this;
    }

    /**
     * Gets the name of the Eloquent user model.
     */
    public function getModel(): string
    {
        return $this->model;
    }

    /**
     * Sets the name of the Eloquent user model.
     */
    public function setModel(string $model): static
    {
        $this->model = $model;

        return $this;
    }

    /**
     * Get the first key from the credential array.
     */
    protected function firstCredentialKey(array $credentials): ?string
    {
        $key = array_key_first($credentials);

        return $key === null ? null : (string) $key;
    }

    /**
     * Get a new query builder for the model instance.
     *
     * @param null|AuthenticatableInterface|Model $model
     */
    protected function newModelQuery(?Model $model = null)
    {
        return is_null($model)
            ? $this->createModel()->newQuery()
            : $model->newQuery();
    }
}
