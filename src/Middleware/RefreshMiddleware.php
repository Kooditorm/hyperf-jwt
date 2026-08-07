<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Middleware;

use Hyperf\Context\Context;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponseInterface;
use Kooditorm\Hyperf\Jwt\Contracts\JWTInterface;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use HyperfExt\Jwt\Token;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Auto-refresh middleware.
 *
 * Mirrors tymon/jwt-auth's RefreshMiddleware — on every successful request,
 * the incoming token is refreshed and the new token is sent back in the
 * `Authorization` response header so the client can rotate its stored token.
 *
 * If the token is expired or blacklisted but still within the refresh window,
 * it is automatically refreshed and the request proceeds normally. If refresh
 * also fails, a 401 is returned.
 *
 * Usage (in config/autoload/middlewares.php):
 *   'http' => [ \HyperfExt\Jwt\Middleware\RefreshMiddleware::class ],
 */
class RefreshMiddleware implements MiddlewareInterface
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
            // Try a normal decode first.
            $this->jwt->decode($token);
            $response = $handler->handle($request);
        } catch (JWTException $e) {
            // Token may be expired or blacklisted — attempt a refresh.
            try {
                $this->jwt->decode($token);
            } catch (JWTException) {
                // Signature is still valid, just expired.
            }

            try {
                /** @var Token $newToken */
                $newToken = $this->jwt->refresh($token);

                // Set the new token for downstream handlers.
                $request = $request->withAttribute('jwt_refreshed_token', $newToken->get());
                Context::set(ServerRequestInterface::class, $request);

                $response = $handler->handle($request);
            } catch (JWTException $refreshEx) {
                return $this->unauthorized($refreshEx->getMessage());
            }
        }

        // Attach the refreshed token to the response.
        $refreshed = $request->getAttribute('jwt_refreshed_token');
        if ($refreshed !== null) {
            $response = $response->withHeader('Authorization', 'Bearer ' . $refreshed);
        }

        return $response;
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
