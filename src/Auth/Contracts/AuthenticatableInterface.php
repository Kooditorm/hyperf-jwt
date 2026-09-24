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

interface AuthenticatableInterface
{
    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier(): mixed;

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string;

    /**
     * Determine whether the password should be checked when validating credentials.
     *
     * @return bool
     */
    public function getCheckAuthPassword(): bool;

    /**
     * Set whether the password should be checked when validating credentials.
     *
     * @param bool $enable
     * @return static
     */
    public function setCheckAuthPassword(bool $enable): static;

    /**
     * Get the token value for the "remember me" session.
     */
    public function getRememberToken(): ?string;

    /**
     * Set the token value for the "remember me" session.
     *
     * @return void
     */
    public function setRememberToken(string $value): void;

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string;
}
