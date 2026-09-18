<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\RequestParser\Handlers;

trait KeyTrait
{
    /**
     * The key.
     */
    protected string $key = 'token';

    /**
     * Set the key.
     */
    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Get the key.
     */
    public function getKey(): string
    {
        return $this->key;
    }
}
