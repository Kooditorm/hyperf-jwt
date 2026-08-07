<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Hyperf\Context\Context;
use Psr\Http\Message\ServerRequestInterface;

class Parser
{
    private array $chain;

    protected ?ServerRequestInterface $request = null;

    public function __construct(?ServerRequestInterface $request = null, array $chain = [])
    {
        $this->request = $request;
        $this->chain = $chain;
    }

    public function getChain(): array
    {
        return $this->chain;
    }

    public function addParser(array|object $parsers): static
    {
        $this->chain = array_merge($this->chain, is_array($parsers) ? $parsers : [$parsers]);

        return $this;
    }

    public function setChain(array $chain): static
    {
        $this->chain = $chain;

        return $this;
    }

    public function setChainOrder(array $chain): static
    {
        return $this->setChain($chain);
    }

    /**
     * Iterate through the parsers and attempt to retrieve a token.
     */
    public function parseToken(): ?string
    {
        foreach ($this->chain as $parser) {
            if ($response = $parser->parse($this->getRequest())) {
                return $response;
            }
        }

        return null;
    }

    public function hasToken(): bool
    {
        return $this->parseToken() !== null;
    }

    public function setRequest(ServerRequestInterface $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the request - uses the explicitly set request, or falls back
     * to the current coroutine's request from context.
     */
    public function getRequest(): ?ServerRequestInterface
    {
        if ($this->request !== null) {
            return $this->request;
        }

        return Context::get(ServerRequestInterface::class);
    }
}
