<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Claims;

class Custom extends AbstractClaim
{
    /**
     * @param mixed $value
     */
    public function __construct(string $name, $value)
    {
        parent::__construct($value);
        $this->setName($name);
    }

    public function validate(bool $ignoreExpired = false): bool
    {
        return true;
    }
}