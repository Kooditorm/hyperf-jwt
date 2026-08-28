<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Validators;

use Hyperf\Contract\ConfigInterface;
use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Contracts\PayloadValidatorInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JwtException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;

class PayloadValidator implements PayloadValidatorInterface
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [];

    public function __construct(ConfigInterface $config)
    {
        $this->setRequiredClaims($config->get('jwt.required_claims', []));
    }

    public function check(Collection $value, bool $ignoreExpired = false): Collection
    {
        $this->validateStructure($value);

        return $this->validatePayload($value, $ignoreExpired);
    }

    public function isValid(Collection $value, bool $ignoreExpired = false): bool
    {
        try {
            $this->check($value, $ignoreExpired);
        } catch (JwtException $e) {
            return false;
        }

        return true;
    }

    /**
     * Set the required claims.
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @throws TokenInvalidException
     */
    protected function validateStructure(Collection $claims)
    {
        if ($this->requiredClaims and ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
        return $this;
    }

    /**
     * Validate the payload timestamps.
     *
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    protected function validatePayload(Collection $claims, bool $ignoreExpired = false): Collection
    {
        return $claims->validate($ignoreExpired);
    }
}