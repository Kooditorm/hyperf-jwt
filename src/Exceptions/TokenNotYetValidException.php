<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Exceptions;

/**
 * Thrown when a token's `nbf` claim is still in the future.
 */
class TokenNotYetValidException extends JWTException
{
}
