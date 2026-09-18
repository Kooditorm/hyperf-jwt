<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Contracts\RequestParser;

use Kooditorm\Hyperf\Jwt\Contracts\RequestParser\HandlerInterface;
use Psr\Http\Message\ServerRequestInterface;

interface RequestParserInterface
{
    /**
     * Get the parser chain.
     *
     * @return array<int, HandlerInterface>
     */
    public function getHandlers(): array;

    /**
     * Set the order of the parser chain.
     *
     * @param array<int, HandlerInterface> $handlers
     *
     * @return $this
     */
    public function setHandlers(array $handlers);

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     */
    public function parseToken(ServerRequestInterface $request): ?string;

    /**
     * Check whether a token exists in the chain.
     */
    public function hasToken(ServerRequestInterface $request): bool;
}
