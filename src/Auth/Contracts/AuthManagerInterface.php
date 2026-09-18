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

/**
 * @method Closure userResolver()
 * @method self resolveUsersUsing(Closure $userResolver)
 * @method void setDefaultDriver(string $name)
 * @method null|UserProviderInterface createUserProvider(?string $provider = null)
 */
interface AuthManagerInterface
{
    /**
     * Get a guard instance by name.
     *
     * Stateful and stateless guards both extend this contract, so the narrowest
     * common type is returned here.
     */
    public function guard(?string $name = null): GuardInterface;

    /**
     * Set the default guard the factory should serve.
     */
    public function shouldUse(string $name): void;

    /**
     * Get the default authentication driver name.
     */
    public function getDefaultDriver(): string;
}
