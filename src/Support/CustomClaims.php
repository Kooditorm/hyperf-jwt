<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Support;

trait CustomClaims
{
    protected array $customClaims = [];

    public function customClaims(array $customClaims): static
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    public function claims(array $customClaims): static
    {
        return $this->customClaims($customClaims);
    }

    public function getCustomClaims(): array
    {
        return $this->customClaims;
    }
}
