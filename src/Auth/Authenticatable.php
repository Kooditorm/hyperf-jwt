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

trait Authenticatable
{
    /**
     * The column name of the "remember me" token.
     */
    protected string $rememberTokenName = 'remember_token';

    /**
     * Determine whether the password should be checked when validating credentials.
     *
     * Set it to false on the model to skip the password verification (e.g. 免密登录 / 第三方登录场景).
     */
    protected bool $checkAuthPassword = true;

    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string
    {
        return $this->getKeyName();
    }

    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): mixed
    {
        return $this->{$this->getAuthIdentifierName()};
    }

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string
    {
        return $this->password;
    }

    /**
     * Determine whether the password should be checked when validating credentials.
     */
    public function getCheckAuthPassword(): bool
    {
        return $this->checkAuthPassword;
    }

    /**
     * Set whether the password should be checked when validating credentials.
     */
    public function setCheckAuthPassword(bool $enable): static
    {
        $this->checkAuthPassword = $enable;

        return $this;
    }

    /**
     * Get the token value for the "remember me" session.
     */
    public function getRememberToken(): ?string
    {
        if (! empty($this->getRememberTokenName())) {
            return (string) $this->{$this->getRememberTokenName()};
        }

        return null;
    }

    /**
     * Set the token value for the "remember me" session.
     */
    public function setRememberToken(string $value): void
    {
        if (! empty($this->getRememberTokenName())) {
            $this->{$this->getRememberTokenName()} = $value;
        }
    }

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string
    {
        return $this->rememberTokenName;
    }
}
