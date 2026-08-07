<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts\Http;

use Psr\Http\Message\ServerRequestInterface;

interface Parser
{
    /**
     * Parse the request and return a token string or null.
     */
    public function parse(ServerRequestInterface $request): ?string;
}
