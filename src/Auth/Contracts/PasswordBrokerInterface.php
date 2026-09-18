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

use Closure;

interface PasswordBrokerInterface
{
    /**
     * Constant representing a successfully sent reminder.
     */
    public const RESET_LINK_SENT = 'passwords.sent';

    /**
     * Constant representing a successfully reset password.
     */
    public const PASSWORD_RESET = 'passwords.reset';

    /**
     * Constant representing the user not found response.
     */
    public const INVALID_USER = 'passwords.user';

    /**
     * Constant representing an invalid token.
     */
    public const INVALID_TOKEN = 'passwords.token';

    /**
     * Constant representing a throttled reset attempt.
     */
    public const RESET_THROTTLED = 'passwords.throttled';

    /**
     * Send a password reset link to a user.
     *
     * @return string one of the broker status constants
     */
    public function sendResetLink(array $credentials): string;

    /**
     * Reset the password for the given token.
     *
     * @return string one of the broker status constants
     */
    public function reset(array $credentials, Closure $callback);
}
