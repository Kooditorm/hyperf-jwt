<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Hyperf\HttpServer\Router\Dispatched;
use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;

class RouteParams implements ParserContract
{
    use KeyTrait;

    public function parse(ServerRequestInterface $request): ?string
    {
        // In Hyperf, route parameters are available via the Dispatched object
        // stored in the request attributes
        $dispatched = $request->getAttribute(Dispatched::class);

        if ($dispatched instanceof Dispatched) {
            $params = $dispatched->handler?->params ?? [];
            return $params[$this->key] ?? null;
        }

        return null;
    }
}
