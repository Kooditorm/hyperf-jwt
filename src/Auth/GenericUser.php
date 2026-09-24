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

use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface as UserContract;
use Kooditorm\Hyperf\Jwt\Contracts\JwtSubjectInterface;

class GenericUser implements UserContract, JwtSubjectInterface
{
    /**
     * All of the user's attributes.
     */
    protected array $attributes;

    /**
     * Create a new generic User object.
     */
    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Dynamically access the user's attributes.
     */
    public function __get(string $key): mixed
    {
        return $this->attributes[$key];
    }

    /**
     * Dynamically set an attribute on the user.
     */
    public function __set(string $key, mixed $value): void
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Dynamically check if a value is set on the user.
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Dynamically unset a value on the user.
     */
    public function __unset(string $key): void
    {
        unset($this->attributes[$key]);
    }

    /**
     * Get the name of the unique identifier for the user.
     */
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): mixed
    {
        return $this->attributes[$this->getAuthIdentifierName()];
    }

    /**
     * Get the password for the user.
     */
    public function getAuthPassword(): ?string
    {
        return $this->attributes['password'];
    }

    /**
     * Determine whether the password should be checked when validating credentials.
     */
    public function getCheckAuthPassword(): bool
    {
        return (bool) ($this->attributes['check_auth_password'] ?? true);
    }

    /**
     * Set whether the password should be checked when validating credentials.
     */
    public function setCheckAuthPassword(bool $enable): static
    {
        $this->attributes['check_auth_password'] = $enable;

        return $this;
    }

    /**
     * Get the "remember me" token value.
     */
    public function getRememberToken(): ?string
    {
        return $this->attributes[$this->getRememberTokenName()];
    }

    /**
     * Set the "remember me" token value.
     */
    public function setRememberToken(string $value): void
    {
        $this->attributes[$this->getRememberTokenName()] = $value;
    }

    /**
     * Get the column name for the "remember me" token.
     */
    public function getRememberTokenName(): ?string
    {
        return 'remember_token';
    }

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     */
    public function getJwtIdentifier(): mixed
    {
        return $this->getAuthIdentifier();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     */
    public function getJwtCustomClaims(): array
    {
        return [];
    }
}
