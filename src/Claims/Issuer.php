<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Claims;

/**
 * `iss` - Issuer: identifies the principal that issued the JWT.
 */
class Issuer extends AbstractClaim
{
    protected string $name = 'iss';
}
