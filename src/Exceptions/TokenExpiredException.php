<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Exceptions;

/**
 * Thrown when a token's `exp` claim is in the past.
 */
class TokenExpiredException extends JWTException
{
}
