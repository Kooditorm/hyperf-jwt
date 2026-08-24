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

use ArrayAccess;
use BadMethodCallException;
use Countable;
use JsonSerializable;
use Hyperf\Context\ApplicationContext;
use Hyperf\Collection\Arr;
use Hyperf\Contract\Arrayable;
use Hyperf\Contract\Jsonable;
use Kooditorm\Hyperf\Jwt\Claims\AbstractClaim;
use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Contracts\PayloadValidatorInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\PayloadException;

use function Hyperf\Support\value;

class Payload implements ArrayAccess, Arrayable, Countable, Jsonable, JsonSerializable
{

}