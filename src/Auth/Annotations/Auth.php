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

use Hyperf\Di\Annotation\AbstractAnnotation;

/**
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class Auth extends AbstractAnnotation
{
    /**
     * @var string[]
     */
    public array $guards = [];

    /**
     * @var bool
     */
    public bool $passable;

    public function __construct($value = null)
    {
        if (!empty($value['value'])) {
            if (!empty($value['value']) && is_array($value['value'])){
                $this->guards = array_unique($value['value']);
            } else {
                $this->guards = [$value['value']];
            }
        }
        if (isset($value['passable'])) {
            $this->passable = (bool) $value['passable'];
        }
    }
}