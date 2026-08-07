<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware that checks for a valid JWT token
 * but does not require authentication. The request continues
 * regardless of token presence/validity.
 */
class JWTCheckMiddleware extends BaseMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->auth->setRequest($request);
            $this->auth->parseToken();
            $this->auth->checkOrFail();
        } catch (JWTException) {
            // Silently continue - this middleware only checks, doesn't enforce
        }

        return $handler->handle($request);
    }
}
