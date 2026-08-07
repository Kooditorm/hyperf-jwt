<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts;

interface Claim
{
    public function setValue(mixed $value): static;

    public function getValue(): mixed;

    public function setName(string $name): static;

    public function getName(): string;

    public function validateCreate(mixed $value): mixed;

    public function validatePayload(): mixed;

    public function validateRefresh(int $refreshTTL): mixed;

    public function matches(mixed $value, bool $strict = true): bool;
}
