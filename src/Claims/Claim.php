<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use JsonSerializable;
use Kooditorm\Hyperf\Jwt\Contracts\Claim as ClaimContract;

abstract class Claim implements ClaimContract, JsonSerializable
{
    protected string $name;

    private mixed $value;

    public function __construct(mixed $value)
    {
        $this->setValue($value);
    }

    public function setValue(mixed $value): static
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    public function getValue(): mixed
    {
        return $this->value;
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function validateCreate(mixed $value): mixed
    {
        return $value;
    }

    public function validatePayload(): mixed
    {
        return $this->getValue();
    }

    public function validateRefresh(int $refreshTTL): mixed
    {
        return $this->getValue();
    }

    public function matches(mixed $value, bool $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    public function __toString(): string
    {
        return $this->toJson();
    }
}
