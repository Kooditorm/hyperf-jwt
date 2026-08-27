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
use InvalidArgumentException;

/**
 * @Annotation
 * @Target("CLASS")
 * @Attributes({
 *     @Attribute("models", type="array")
 * })
 */
class Policy extends AbstractAnnotation
{
    /**
     * @var string[]
     */
    public $models;

    public function __construct($value = null, $aa = null)
    {
        if (isset($value['value'])) {
            $value['value'] = empty($value['value']) ? [] : (is_array($value['value']) ? array_unique($value['value']) : [$value['value']]);
            if (empty($value['value'])) {
                throw new InvalidArgumentException('Policy annotation requires at least one model.');
            }
            $this->models = $value['value'];
        }
    }
}