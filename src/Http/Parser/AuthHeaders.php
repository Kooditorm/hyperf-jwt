<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;

class AuthHeaders implements ParserContract
{
    protected string $header = 'authorization';

    protected string $prefix = 'bearer';

    /**
     * Attempt to parse the token from alternative server params.
     */
    protected function fromAltHeaders(ServerRequestInterface $request): ?string
    {
        $serverParams = $request->getServerParams();

        return $serverParams['HTTP_AUTHORIZATION'] ?? $serverParams['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine($this->header);

        if (empty($header)) {
            $header = $this->fromAltHeaders($request) ?? '';
        }

        if (! empty($header)) {
            $position = strripos($header, $this->prefix);

            if ($position !== false) {
                $header = substr($header, $position + strlen($this->prefix));

                return trim(
                    strpos($header, ',') !== false ? strstr($header, ',', true) : $header
                );
            }
        }

        return null;
    }

    public function setHeaderName(string $headerName): static
    {
        $this->header = $headerName;

        return $this;
    }

    public function setHeaderPrefix(string $headerPrefix): static
    {
        $this->prefix = $headerPrefix;

        return $this;
    }
}
