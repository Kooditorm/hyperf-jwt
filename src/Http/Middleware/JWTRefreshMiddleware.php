<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;

/**
 * PSR-15 middleware that refreshes the JWT token and
 * returns it in the Authorization header of the response.
 */
class JWTRefreshMiddleware extends BaseMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->auth->setRequest($request);

            // Ensure a token exists
            if (! $this->auth->parser()->hasToken()) {
                return $this->errorResponse('Token not provided');
            }

            // Refresh the token (this also validates the old token)
            $newToken = $this->auth->refresh();
        } catch (JWTException $e) {
            return $this->errorResponse($e->getMessage());
        }

        $response = $handler->handle($request);

        return $this->setAuthenticationHeader($response, $newToken);
    }
}
