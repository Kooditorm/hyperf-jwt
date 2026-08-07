<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

class Issuer extends Claim
{
    protected string $name = 'iss';
}
