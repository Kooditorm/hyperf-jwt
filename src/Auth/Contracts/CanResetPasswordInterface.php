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

interface CanResetPasswordInterface
{
    /**
     * Get the e-mail address where password reset links are sent.
     */
    public function getEmailForPasswordReset(): string;

    /**
     * Send the password reset notification.
     */
    public function sendPasswordResetNotification(string $token): void;
}