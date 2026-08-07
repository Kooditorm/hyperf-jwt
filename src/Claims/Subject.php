<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

class Subject extends Claim
{
    protected string $name = 'sub';
}
