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

use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Auth\Exceptions\AuthenticationException;

/**
 * These methods are typically the same across all guards.
 */
trait GuardHelpers
{
    /**
     * The currently authenticated user.
     */
    protected ?AuthenticatableInterface $user = null;

    /**
     * The user provider implementation.
     */
    protected UserProviderInterface $provider;

    /**
     * Determine if current user is authenticated. If not, throw an exception.
     *
     * @throws AuthenticationException
     */
    public function authenticate(): AuthenticatableInterface
    {
        if (! is_null($user = $this->user())) {
            return $user;
        }

        throw new AuthenticationException();
    }

    /**
     * Determine if the guard has a user instance.
     */
    public function hasUser(): bool
    {
        return ! is_null($this->user);
    }

    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool
    {
        return ! is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return null|int|string
     */
    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }

        return null;
    }

    /**
     * Set the current user.
     */
    public function setUser(AuthenticatableInterface $user): static
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     */
    public function getProvider(): UserProviderInterface
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     */
    public function setProvider(UserProviderInterface $provider): static
    {
        $this->provider = $provider;

        return $this;
    }
}
