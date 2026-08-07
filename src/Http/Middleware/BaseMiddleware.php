<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Middleware;

use Hyperf\HttpMessage\Contract\ResponseInterface as HttpResponseInterface;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\JWTAuth;

abstract class BaseMiddleware implements MiddlewareInterface
{
    protected JWTAuth $auth;

    protected ContainerInterface $container;

    protected HttpResponseInterface $response;

    public function __construct(JWTAuth $auth, ContainerInterface $container, HttpResponseInterface $response)
    {
        $this->auth = $auth;
        $this->container = $container;
        $this->response = $response;
    }

    /**
     * Check the request for the presence of a token.
     */
    public function checkForToken(ServerRequestInterface $request): void
    {
        $this->auth->setRequest($request);

        if (! $this->auth->parser()->hasToken()) {
            throw new JWTException('Token not provided');
        }
    }

    /**
     * Attempt to authenticate a user via the token in the request.
     */
    public function authenticate(ServerRequestInterface $request): void
    {
        $this->checkForToken($request);

        if (! $this->auth->parseToken()->authenticate()) {
            throw new JWTException('User not found');
        }
    }

    /**
     * Set the authentication header on the response.
     */
    protected function setAuthenticationHeader(ResponseInterface $response, ?string $token = null): ResponseInterface
    {
        $token = $token ?: $this->auth->refresh();

        return $response->withHeader('Authorization', 'Bearer ' . $token);
    }

    /**
     * Create a JSON error response.
     */
    protected function errorResponse(string $message, int $status = 401): ResponseInterface
    {
        $body = json_encode([
            'code' => $status,
            'message' => $message,
        ], JSON_UNESCAPED_UNICODE);

        return $this->response
            ->withStatus($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody(new SwooleStream($body));
    }
}
