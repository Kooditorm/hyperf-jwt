<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Exceptions;

/**
 * Thrown when a token has been revoked (present in the blacklist).
 */
class TokenBlacklistedException extends JWTException
{
}
