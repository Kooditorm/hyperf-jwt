<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\RequestParser\Handlers;

use Kooditorm\Hyperf\Jwt\Contracts\RequestParser\HandlerInterface as ParserContract;
use Psr\Http\Message\ServerRequestInterface;
use Hyperf\HttpServer\Request;

class RouteParams implements ParserContract
{
    use KeyTrait;

    /**
     * @param Request|ServerRequestInterface $request
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        return $request->route($this->key);
    }
}