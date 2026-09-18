<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Guards;

use Hyperf\Context\ApplicationContext;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Macroable\Macroable;
use InvalidArgumentException;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Contracts\StatelessGuardInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Auth\GuardHelpers;
use Kooditorm\Hyperf\Jwt\Contracts\JwtSubjectInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JwtException;
use Kooditorm\Hyperf\Jwt\Jwt;
use Psr\Container\ContainerInterface;

class JwtGuard implements StatelessGuardInterface
{
    use GuardHelpers;
    use Macroable {
        __call as macroCall;
    }

    /**
     * The name of the Guard. Typically "jwt".
     *
     * Corresponds to guard name in authentication configuration.
     */
    protected string $name;

    /**
     * The user we last attempted to retrieve.
     */
    protected ?AuthenticatableInterface $lastAttempted = null;

    protected ContainerInterface $container;

    protected Jwt $jwt;

    protected RequestInterface $request;

    /**
     * Create a new authentication guard.
     */
    public function __construct(
        UserProviderInterface $provider,
        string $name,
        array $options = []
    ) {
        $this->provider = $provider;
        $this->name = $name;
        $this->container = ApplicationContext::getContainer();
        $this->jwt = $this->container->get(Jwt::class);
        $this->request = $this->container->get(RequestInterface::class);
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticatableInterface
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $this->jwt->getToken()) {
            return $this->user = null;
        }

        try {
            $user = $this->provider->retrieveById($this->jwt->getPayload()->get('sub'));
        } catch (JwtException $e) {
            $user = null;
        }

        return $this->user = $user;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @return bool|string the token when logging in, otherwise a boolean state
     */
    public function attempt(array $credentials = [], bool $login = true): bool|string
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log a user into the application, create a token for the user.
     *
     * @return string the freshly issued token
     *
     * @throws InvalidArgumentException when the user does not implement JwtSubjectInterface
     */
    public function login(AuthenticatableInterface $user): string
    {
        if (! $user instanceof JwtSubjectInterface) {
            throw new InvalidArgumentException(
                sprintf(
                    'User [%s] must implement [%s].',
                    get_class($user),
                    JwtSubjectInterface::class
                )
            );
        }

        $this->setUser($user);

        return $this->jwt->fromUser($user);
    }

    /**
     * Log the given user ID into the application.
     *
     * @return bool|string the token when found, otherwise false
     */
    public function loginUsingId(mixed $id): bool|string
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            return $this->login($user);
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
    public function onceUsingId(mixed $id): bool
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Log the user out of the application, thus invalidating the token.
     */
    public function logout(bool $forceForever = false): void
    {
        try {
            $this->jwt->invalidate($forceForever);
        } catch (JwtException $e) {
            // The token may already be invalid or missing; nothing to do.
        }

        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     */
    public function refresh(bool $forceForever = false): string
    {
        return $this->jwt->refresh($forceForever);
    }

    /**
     * Invalidate the token.
     */
    public function invalidate(bool $forceForever = false): Jwt
    {
        return $this->jwt->invalidate($forceForever);
    }

    /**
     * Determine if the user matches the credentials.
     */
    protected function hasValidCredentials(?AuthenticatableInterface $user, array $credentials): bool
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }
}
