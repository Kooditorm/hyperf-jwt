<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Exceptions;

/**
 * Thrown when a token's `nbf` claim is still in the future.
 */
class TokenNotYetValidException extends JWTException
{
}
