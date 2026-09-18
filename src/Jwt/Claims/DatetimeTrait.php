<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Claims;

use DateInterval;
use DateTimeInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\InvalidClaimException;
use Kooditorm\Hyperf\Jwt\Utils;

trait DatetimeTrait
{
    /**
     * Time leeway in seconds.
     */
    protected int $leeway = 0;

    /**
     * Set the claim value, and call a validate method.
     *
     * @throws InvalidClaimException
     *
     * @return $this
     */
    public function setValue(mixed $value)
    {
        if ($value instanceof DateInterval) {
            $value = Utils::now()->add($value);
        }

        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }

    /**
     * {@inheritdoc}
     */
    public function validateCreate(mixed $value)
    {
        if (! is_numeric($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    /**
     * Set the leeway in seconds.
     */
    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Determine whether the value is in the future.
     */
    protected function isFuture(mixed $value): bool
    {
        return Utils::isFuture((int) $value, (int) $this->leeway);
    }

    /**
     * Determine whether the value is in the past.
     */
    protected function isPast(mixed $value): bool
    {
        return Utils::isPast((int) $value, (int) $this->leeway);
    }
}
