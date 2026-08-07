<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Exceptions;

/**
 * Thrown when a token is malformed or its payload fails structural validation.
 */
class TokenInvalidException extends JWTException
{
}
