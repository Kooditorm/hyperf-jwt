<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Middleware;

use Hyperf\Context\Context;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponseInterface;
use HyperfExt\Jwt\Contracts\JWTInterface;
use HyperfExt\Jwt\Exceptions\JWTException;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Example authentication middleware.
 *
 * Extracts a bearer token from the `Authorization` header, validates it, and
 * stores the decoded claims in the request attribute `jwt_claims`. On failure
 * it responds with 401 JSON.
 *
 * Usage (in config/autoload/middlewares.php):
 *   'http' => [ \HyperfExt\Jwt\Middleware\JwtAuthMiddleware::class ],
 */
class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        protected ContainerInterface $container,
        protected JWTInterface $jwt
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->parseToken($request);

        if ($token === null) {
            return $this->unauthorized('Token not provided.');
        }

        try {
            $payload = $this->jwt->decode($token);
            $claims = $payload->toArray();
        } catch (JWTException $e) {
            return $this->unauthorized($e->getMessage());
        }

        // Make claims available to controllers via request attribute + context.
        $request = $request->withAttribute('jwt_claims', $claims);
        Context::set(ServerRequestInterface::class, $request);

        return $handler->handle($request);
    }

    /**
     * Read the bearer token from the Authorization header or a `token` query param.
     */
    protected function parseToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if ($header !== '' && preg_match('/Bearer\s+(.*)$/i', $header, $matches)) {
            return trim($matches[1]);
        }

        $query = $request->getQueryParams()['token'] ?? null;
        if (is_string($query) && $query !== '') {
            return $query;
        }

        return null;
    }

    protected function unauthorized(string $message): ResponseInterface
    {
        $response = $this->container->get(HttpResponseInterface::class);

        $body = json_encode([
            'code' => 401,
            'message' => $message,
        ], JSON_UNESCAPED_UNICODE);

        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json')
            ->withBody(new SwooleStream((string) $body));
    }
}
