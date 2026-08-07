<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts;

interface Validator
{
    public function isValid(mixed $value): bool;

    public function check(mixed $value): mixed;
}
