<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

trait KeyTrait
{
    protected string $key = 'token';

    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    public function getKey(): string
    {
        return $this->key;
    }
}
