<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Contracts\Access;

interface Authorizable
{
    /**
     * Determine if the entity has the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     */
    public function can(iterable|string $abilities, mixed $arguments = []): bool;
}
