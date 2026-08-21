<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Hash;

use Kooditorm\Hyperf\Hash\Contract\TestInterface;

class TestManager extends Test implements TestInterface
{

    public function info()
    {
        return 'test';
    }
}