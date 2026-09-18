<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Contracts;

interface StorageInterface
{
    public function add(string $key, mixed $value, int $ttl);

    public function forever(string $key, mixed $value);

    /**
     * @return mixed
     */
    public function get(string $key);

    public function destroy(string $key): bool;

    public function flush(): void;
}
