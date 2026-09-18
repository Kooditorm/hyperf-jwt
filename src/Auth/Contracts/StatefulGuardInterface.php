<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Contracts;

interface StatefulGuardInterface extends GuardInterface
{
    /**
     * Attempt to authenticate a user using the given credentials.
     */
    public function attempt(array $credentials = [], bool $remember = false): bool;

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool;

    /**
     * Log a user into the application.
     */
    public function login(AuthenticatableInterface $user, bool $remember = false): void;

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     * @param bool $remember
     * @return AuthenticatableInterface|null
     */
    public function loginUsingId(mixed $id, bool $remember = false): ?AuthenticatableInterface;

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     *
     * @return bool|AuthenticatableInterface
     */
    public function onceUsingId(mixed $id): AuthenticatableInterface|bool;

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool;

    /**
     * Log the user out of the application.
     */
    public function logout(): void;
}
