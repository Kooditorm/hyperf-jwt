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
use Hyperf\Database\ConnectionInterface;
use Hyperf\Database\ConnectionResolverInterface;
use Hyperf\Stringable\Str;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Auth\GenericUser;
use Kooditorm\Hyperf\Hash\Contract\DriverInterface;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;

class DatabaseUserProvider implements UserProviderInterface
{
    /**
     * The active database connection.
     */
    protected ConnectionInterface $conn;

    /**
     * The hasher implementation.
     */
    protected DriverInterface $hasher;

    /**
     * The table containing the users.
     */
    protected string $table;

    /**
     * Create a new database user provider.
     */
    public function __construct(
        ConnectionResolverInterface $connectionResolver,
        HashInterface $hash,
        array $options
    ) {
        $this->conn = ($connection = $options['connection'] ?? null) instanceof ConnectionInterface
            ? $connection
            : $connectionResolver->connection($connection);
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof DriverInterface
            ? $hasher
            : $hash->getDriver($hasher);
        $this->table = $options['table'] ?? null;
    }

    public function retrieveById(mixed $identifier): ?AuthenticatableInterface
    {
        $user = $this->conn->table($this->table)->find($identifier);

        return $this->getGenericUser($user);
    }

    public function retrieveByToken(mixed $identifier, string $token): ?AuthenticatableInterface
    {
        $user = $this->getGenericUser(
            $this->conn->table($this->table)->find($identifier)
        );

        return $user && $user->getRememberToken() && hash_equals($user->getRememberToken(), $token)
            ? $user : null;
    }

    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $this->conn->table($this->table)
            ->where($user->getAuthIdentifierName(), $user->getAuthIdentifier())
            ->update([$user->getRememberTokenName() => $token]);
    }

    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (
            empty($credentials)
            || (count($credentials) === 1 && array_key_exists('password', $credentials))
        ) {
            return null;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // generic "user" object that will be utilized by the Guard instances.
        $query = $this->conn->table($this->table);

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

        // Now we are ready to execute the query to see if we have an user matching
        // the given credentials. If not, we will just return nulls and indicate
        // that there are no matching users for these given credential arrays.
        $user = $query->first();

        return $this->getGenericUser($user);
    }

    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool
    {
        return $this->hasher->check(
            $credentials['password'],
            $user->getAuthPassword()
        );
    }

    /**
     * Get the generic user.
     */
    protected function getGenericUser(mixed $user): ?GenericUser
    {
        if (! is_null($user)) {
            return new GenericUser((array) $user);
        }

        return null;
    }
}
