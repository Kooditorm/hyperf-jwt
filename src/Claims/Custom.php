<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

class Custom extends Claim
{
    public function __construct(string $name, mixed $value)
    {
        $this->setName($name);
        parent::__construct($value);
    }
}
