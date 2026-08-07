<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;

/**
 * PSR-15 middleware that authenticates the user via JWT.
 * Returns 401 if the token is missing, invalid, or the user is not found.
 */
class JWTAuthMiddleware extends BaseMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->authenticate($request);
        } catch (JWTException $e) {
            return $this->errorResponse($e->getMessage());
        }

        return $handler->handle($request);
    }
}
