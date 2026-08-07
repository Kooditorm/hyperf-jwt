<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use DateInterval;
use DateTimeInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\InvalidClaimException;
use Kooditorm\Hyperf\Jwt\Support\Utils;

trait DatetimeTrait
{
    protected int $leeway = 0;

    public function setValue(mixed $value): static
    {
        if ($value instanceof DateInterval) {
            $value = Utils::now()->add($value);
        }

        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }

    public function validateCreate(mixed $value): mixed
    {
        if (! is_numeric($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    protected function isFuture(int $value): bool
    {
        return Utils::isFuture($value, $this->leeway);
    }

    protected function isPast(int $value): bool
    {
        return Utils::isPast($value, $this->leeway);
    }

    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }
}
