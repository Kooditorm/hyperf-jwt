<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Support;

trait RefreshFlow
{
    protected bool $refreshFlow = false;

    public function setRefreshFlow(bool $refreshFlow = true): static
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
