<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;

/**
 * PSR-15 middleware that authenticates the user AND refreshes the token.
 * The new token is returned in the Authorization header of the response.
 */
class JWTAuthAndRenewMiddleware extends BaseMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->authenticate($request);
        } catch (JWTException $e) {
            return $this->errorResponse($e->getMessage());
        }

        $response = $handler->handle($request);

        try {
            $newToken = $this->auth->refresh();
            $response = $this->setAuthenticationHeader($response, $newToken);
        } catch (JWTException $e) {
            return $this->errorResponse($e->getMessage());
        }

        return $response;
    }
}
