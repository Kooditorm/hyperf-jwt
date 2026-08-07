<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

/**
 * `iss` - Issuer: identifies the principal that issued the JWT.
 */
class Issuer extends AbstractClaim
{
    protected string $name = 'iss';
}
