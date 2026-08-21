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

interface GuardInterface
{
    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool;

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool;

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticatableInterface;

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return null|int|string
     */
    public function id();

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool;

    /**
     * Set the current user.
     *
     * @return static
     */
    public function setUser(AuthenticatableInterface $user);
}