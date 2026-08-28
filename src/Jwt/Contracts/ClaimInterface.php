<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Contracts;

use Kooditorm\Hyperf\Jwt\Exceptions\InvalidClaimException;

interface ClaimInterface
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param mixed $value
     *
     * @throws InvalidClaimException
     *
     * @return $this
     */
    public function setValue($value);

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name);

    /**
     * Get the claim name.
     */
    public function getName(): string;

    /**
     * Validate the Claim value.
     */
    public function validate(bool $ignoreExpired = false): bool;
}