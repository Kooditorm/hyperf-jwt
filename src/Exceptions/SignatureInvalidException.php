<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Exceptions;

/**
 * Thrown when the token signature cannot be verified.
 */
class SignatureInvalidException extends JWTException
{
}
