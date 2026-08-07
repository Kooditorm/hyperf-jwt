<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Validators;

use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    protected array $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    protected ?int $refreshTTL = 20160;

    public function check($value): Collection
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    protected function validateStructure(Collection $claims): void
    {
        if ($this->requiredClaims && ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    protected function validatePayload(Collection $claims): Collection
    {
        return $claims->validate('payload');
    }

    protected function validateRefresh(Collection $claims): Collection
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    public function setRequiredClaims(array $claims): static
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    public function getRequiredClaims(): array
    {
        return $this->requiredClaims;
    }

    public function setRefreshTTL(?int $ttl): static
    {
        $this->refreshTTL = $ttl !== null ? (int) $ttl : null;

        return $this;
    }

    public function getRefreshTTL(): ?int
    {
        return $this->refreshTTL;
    }
}
