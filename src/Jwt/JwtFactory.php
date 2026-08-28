<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt;

use Hyperf\Contract\ConfigInterface;
use HyperfExtension\Jwt\Contracts\JwtFactoryInterface;

use function Hyperf\Support\make;

class JwtFactory implements JwtFactoryInterface
{
    protected $lockSubject = true;

    public function __construct(ConfigInterface $config)
    {
        $this->lockSubject = (bool) $config->get('jwt.lock_subject');
    }

    public function make(): Jwt
    {
        return make(Jwt::class)->setLockSubject($this->lockSubject);
    }
}