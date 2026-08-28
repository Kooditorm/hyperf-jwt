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

use Kooditorm\Hyperf\Jwt\RequestParser\Handlers\AuthHeaders;
use Kooditorm\Hyperf\Jwt\RequestParser\Handlers\Cookies;
use Kooditorm\Hyperf\Jwt\RequestParser\Handlers\InputSource;
use Kooditorm\Hyperf\Jwt\RequestParser\Handlers\QueryString;
use Kooditorm\Hyperf\Jwt\RequestParser\Handlers\RouteParams;

use function Hyperf\Support\make;
class RequestParserFactory
{
    public function __invoke()
    {
        return make(RequestParser::class)->setHandlers([
            new AuthHeaders(),
            new QueryString(),
            new InputSource(),
            new RouteParams(),
            new Cookies(),
        ]);
    }
}