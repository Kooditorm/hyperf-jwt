<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

class Audience extends Claim
{
    protected string $name = 'aud';
}
