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
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

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
     * @param array $credentials
     * @param bool $login
     * @return bool|string the token when logging in, otherwise a boolean state
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
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
     * @param AuthenticatableInterface $user
     * @return string the freshly issued token
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function login(AuthenticatableInterface $user): string
    {

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
     * @param bool $forceForever
     * @throws ContainerExceptionInterface
     * @throws JwtException
     * @throws NotFoundExceptionInterface
     */
    public function logout(bool $forceForever = false): void
    {
        $this->jwt->invalidate($forceForever);
        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     * @param bool $forceForever
     * @return string
     * @throws ContainerExceptionInterface
     * @throws JwtException
     * @throws NotFoundExceptionInterface
     */
    public function refresh(bool $forceForever = false): string
    {
        return $this->jwt->refresh($forceForever);
    }

    /**
     * Invalidate the token.
     * @param bool $forceForever
     * @return Jwt
     * @throws JwtException
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
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
        if (is_null($user)) {
            return false;
        }

        // 关闭密码校验时（getCheckAuthPassword() 返回 false），跳过密码比对直接视为凭证有效
        if (! $user->getCheckAuthPassword()) {
            return true;
        }

        return $this->provider->validateCredentials($user, $credentials);
    }
}
