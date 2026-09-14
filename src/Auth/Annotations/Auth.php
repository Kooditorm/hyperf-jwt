<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Annotations;

use Attribute;
use Hyperf\Di\Annotation\AbstractAnnotation;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class Auth extends AbstractAnnotation
{
    /**
     * @var array
     */
    public array $guards;

    /**
     * @var bool
     */
    public bool $passable;

    public function __construct(array|string|null $guards = null, bool $passable = false)
    {
        $guards = is_null($guards) ? [] : $guards;
        $this->guards = is_array($guards) ? array_unique($guards) : [$guards];
        $this->passable = $passable;

    }
}