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

use Kooditorm\Hyperf\Auth\Contracts\CanResetPasswordInterface as CanResetPasswordContract;

interface TokenRepositoryInterface
{
    /**
     * Create a new token.
     */
    public function create(CanResetPasswordContract $user): string;

    /**
     * Determine if a token record exists and is valid.
     */
    public function exists(CanResetPasswordContract $user, string $token): bool;

    /**
     * Determine if the given user recently created a password reset token.
     */
    public function recentlyCreatedToken(CanResetPasswordContract $user): bool;

    /**
     * Delete a token record.
     */
    public function delete(CanResetPasswordContract $user): void;

    /**
     * Delete expired tokens.
     */
    public function deleteExpired(): void;
}