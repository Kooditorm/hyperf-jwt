<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

/**
 * `sub` - Subject: identifies the principal that is the subject of the JWT.
 */
class Subject extends AbstractClaim
{
    protected string $name = 'sub';
}
