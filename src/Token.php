<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Validators\TokenValidator;

class Token
{
    private string $value;

    public function __construct(string $value)
    {
        $this->value = (string) (new TokenValidator())->check($value);
    }

    public function get(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->get();
    }
}
