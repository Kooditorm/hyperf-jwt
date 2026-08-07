<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Exceptions;

/**
 * Thrown when the token signature cannot be verified.
 */
class SignatureInvalidException extends JWTException
{
}
