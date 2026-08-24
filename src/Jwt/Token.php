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

use Hyperf\Context\ApplicationContext;
use Kooditorm\Hyperf\Jwt\Contracts\TokenValidatorInterface;
class Token
{
    /**
     * @var string
     */
    private $value;

    /**
     * @var \Kooditorm\Hyperf\Jwt\Contracts\TokenValidatorInterface
     */
    private $validator;

    /**
     * Create a new JSON Web Token.
     */
    public function __construct(string $value)
    {
        $this->validator = ApplicationContext::getContainer()->get(TokenValidatorInterface::class);
        $this->value = (string) $this->validator->check($value);
    }

    /**
     * Get the token when casting to string.
     */
    public function __toString(): string
    {
        return $this->get();
    }

    /**
     * Get the token.
     */
    public function get(): string
    {
        return $this->value;
    }
}