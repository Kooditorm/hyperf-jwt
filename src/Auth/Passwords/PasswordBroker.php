<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Passwords;

use Closure;
use Hyperf\Collection\Arr;
use Kooditorm\Hyperf\Auth\Contracts\CanResetPasswordInterface;
use Kooditorm\Hyperf\Auth\Contracts\PasswordBrokerInterface;
use Kooditorm\Hyperf\Auth\Contracts\TokenRepositoryInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use UnexpectedValueException;

class PasswordBroker implements PasswordBrokerInterface
{
    /**
     * The password token repository.
     *
     * @var TokenRepositoryInterface
     */
    protected $tokens;

    /**
     * The user provider implementation.
     *
     * @var UserProviderInterface
     */
    protected $users;

    /**
     * Create a new password broker instance.
     */
    public function __construct(TokenRepositoryInterface $tokens, UserProviderInterface $users)
    {
        $this->users = $users;
        $this->tokens = $tokens;
    }

    /**
     * Send a password reset link to a user.
     */
    public function sendResetLink(array $credentials): string
    {
        // First we will check to see if we found a user at the given credentials and
        // if we did not we will redirect back to this current URI with a piece of
        // "flash" data in the session to indicate to the developers the errors.
        $user = $this->getUser($credentials);

        if (is_null($user)) {
            return static::INVALID_USER;
        }

        if ($this->tokens->recentlyCreatedToken($user)) {
            return static::RESET_THROTTLED;
        }

        // Once we have the reset token, we are ready to send the message out to this
        // user with a link to reset their password. We will then redirect back to
        // the current URI having nothing set in the session to indicate errors.
        $user->sendPasswordResetNotification(
            $this->tokens->create($user)
        );

        return static::RESET_LINK_SENT;
    }

    /**
     * Reset the password for the given token.
     *
     * @return mixed
     */
    public function reset(array $credentials, Closure $callback)
    {
        $user = $this->validateReset($credentials);

        // If the responses from the validate method is not a user instance, we will
        // assume that it is a redirect and simply return it from this method and
        // the user is properly redirected having an error message on the post.
        if (!$user instanceof CanResetPasswordInterface) {
            return $user;
        }

        $password = $credentials['password'];

        // Once the reset has been validated, we'll call the given callback with the
        // new password. This gives the user an opportunity to store the password
        // in their persistent storage. Then we'll delete the token and return.
        $callback($user, $password);

        $this->tokens->delete($user);

        return static::PASSWORD_RESET;
    }

    /**
     * Get the user for the given credentials.
     *
     * @throws \UnexpectedValueException
     */
    public function getUser(array $credentials): ?CanResetPasswordInterface
    {
        $credentials = Arr::except($credentials, ['token']);

        $user = $this->users->retrieveByCredentials($credentials);

        if ($user && !$user instanceof CanResetPasswordInterface) {
            throw new UnexpectedValueException('User must implement CanResetPassword interface.');
        }

        return $user;
    }

    /**
     * Create a new password reset token for the given user.
     */
    public function createToken(CanResetPasswordInterface $user): string
    {
        return $this->tokens->create($user);
    }

    /**
     * Delete password reset tokens of the given user.
     */
    public function deleteToken(CanResetPasswordInterface $user): void
    {
        $this->tokens->delete($user);
    }

    /**
     * Validate the given password reset token.
     */
    public function tokenExists(CanResetPasswordInterface $user, string $token): bool
    {
        return $this->tokens->exists($user, $token);
    }

    /**
     * Get the password reset token repository implementation.
     */
    public function getRepository(): TokenRepositoryInterface
    {
        return $this->tokens;
    }

    /**
     * Validate a password reset for the given credentials.
     *
     * @return CanResetPasswordInterface|string
     */
    protected function validateReset(array $credentials)
    {
        if (is_null($user = $this->getUser($credentials))) {
            return static::INVALID_USER;
        }

        if (!$this->tokens->exists($user, $credentials['token'])) {
            return static::INVALID_TOKEN;
        }

        return $user;
    }
}