<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\RequestParser;

use Kooditorm\Hyperf\Jwt\Contracts\RequestParser\HandlerInterface;
use Kooditorm\Hyperf\Jwt\Contracts\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestParser implements RequestParserInterface
{
    /**
     * @var array<int, HandlerInterface>
     */
    private array $handlers;

    /**
     * @param array<int, HandlerInterface> $handlers
     */
    public function __construct(array $handlers = [])
    {
        $this->handlers = $handlers;
    }

    public function getHandlers(): array
    {
        return $this->handlers;
    }

    public function setHandlers(array $handlers): static
    {
        $this->handlers = $handlers;

        return $this;
    }

    public function parseToken(ServerRequestInterface $request): ?string
    {
        foreach ($this->handlers as $handler) {
            if ($token = $handler->parse($request)) {
                return $token;
            }
        }

        return null;
    }

    public function hasToken(ServerRequestInterface $request): bool
    {
        return $this->parseToken($request) !== null;
    }
}
