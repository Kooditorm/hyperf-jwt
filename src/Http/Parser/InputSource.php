<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;

class InputSource implements ParserContract
{
    use KeyTrait;

    public function parse(ServerRequestInterface $request): ?string
    {
        // Check parsed body first (POST data)
        $body = $request->getParsedBody();
        if (is_array($body) && isset($body[$this->key])) {
            return $body[$this->key];
        }

        // Fallback to query params
        $query = $request->getQueryParams();
        return $query[$this->key] ?? null;
    }
}
