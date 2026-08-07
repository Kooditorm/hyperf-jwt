<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;

class QueryString implements ParserContract
{
    use KeyTrait;

    public function parse(ServerRequestInterface $request): ?string
    {
        $query = $request->getQueryParams();

        return $query[$this->key] ?? null;
    }
}
