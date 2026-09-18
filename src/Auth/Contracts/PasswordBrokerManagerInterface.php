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

/**
 * Calls that are not declared on the manager are forwarded to the default broker.
 *
 * @method string sendResetLink(array $credentials)
 * @method string reset(array $credentials, \Closure $callback)
 * @method null|CanResetPasswordInterface getUser(array $credentials)
 * @method string createToken(CanResetPasswordInterface $user)
 * @method void deleteToken(CanResetPasswordInterface $user)
 * @method bool tokenExists(CanResetPasswordInterface $user, string $token)
 * @method TokenRepositoryInterface getRepository()
 */
interface PasswordBrokerManagerInterface
{
    /**
     * Get a password broker instance by name.
     */
    public function broker(?string $name = null): PasswordBrokerInterface;
}
