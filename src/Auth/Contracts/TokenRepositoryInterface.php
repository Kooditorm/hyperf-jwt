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

interface TokenRepositoryInterface
{
    /**
     * Create a new token.
     */
    public function create(CanResetPasswordInterface $user): string;

    /**
     * Determine if a token record exists and is valid.
     */
    public function exists(CanResetPasswordInterface $user, string $token): bool;

    /**
     * Determine if the given user recently created a password reset token.
     */
    public function recentlyCreatedToken(CanResetPasswordInterface $user): bool;

    /**
     * Delete a token record.
     */
    public function delete(CanResetPasswordInterface $user): void;

    /**
     * Delete expired tokens.
     */
    public function deleteExpired(): void;
}
