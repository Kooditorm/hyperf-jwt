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
use Kooditorm\Hyperf\Jwt\Claims\Factory as ClaimFactory;
use Kooditorm\Hyperf\Jwt\Contracts\CodecInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\InvalidConfigException;
use Kooditorm\Hyperf\Jwt\Storage\HyperfCache;
use Psr\Container\ContainerInterface;
class ManagerFactory
{

}