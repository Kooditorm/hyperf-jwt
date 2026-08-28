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

use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;

interface PayloadValidatorInterface
{
    /**
     * Perform some checks on the value.
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function check(Collection $value, bool $ignoreExpired = false): Collection;

    /**
     * Helper function to return a boolean.
     */
    public function isValid(Collection $value, bool $ignoreExpired = false): bool;
}