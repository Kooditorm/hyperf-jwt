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

interface StatelessGuardInterface extends GuardInterface
{
    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @return bool|string the token when logging in, otherwise a boolean state
     */
    public function attempt(array $credentials = [], bool $login = true);

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool;

    /**
     * Log a user into the application and create a token for the user.
     *
     * @return string the freshly issued token
     */
    public function login(AuthenticatableInterface $user);

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     *
     * @return bool|string the token when found, otherwise false
     */
    public function loginUsingId(mixed $id);

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     */
    public function onceUsingId(mixed $id): bool;

    /**
     * Log the user out of the application, thus invalidating the token.
     */
    public function logout(bool $forceForever = false);

    /**
     * Refresh the token.
     *
     * @return string
     */
    public function refresh(bool $forceForever = false);

    /**
     * Invalidate the token.
     *
     * @return mixed
     */
    public function invalidate(bool $forceForever = false);
}
