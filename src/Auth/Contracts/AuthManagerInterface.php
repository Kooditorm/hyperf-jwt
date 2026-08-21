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
interface AuthManagerInterface
{
    /**
     * Get a guard instance by name.
     *
     * @return \Kooditorm\Hyperf\Auth\Contracts\GuardInterface|\Kooditorm\Hyperf\Auth\Contracts\StatefulGuardInterface|\Kooditorm\Hyperf\Auth\Contracts\StatelessGuardInterface
     */
    public function guard(?string $name = null): GuardInterface;

    /**
     * Set the default guard the factory should serve.
     */
    public function shouldUse(string $name): void;
}