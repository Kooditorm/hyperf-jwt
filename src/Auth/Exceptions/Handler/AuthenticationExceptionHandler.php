<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Exceptions\Handler;

use Hyperf\Codec\Json;
use Hyperf\ExceptionHandler\ExceptionHandler;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Kooditorm\Hyperf\Auth\Exceptions\AuthenticationException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;
use Hyperf\ExceptionHandler\Annotation\ExceptionHandler as RegisterHandler;

#[RegisterHandler(server: 'http')]
class AuthenticationExceptionHandler extends ExceptionHandler
{
    public function handle(Throwable $throwable, ResponseInterface $response): MessageInterface|ResponseInterface
    {
        if ($throwable instanceof AuthenticationException) {
            return $response->withStatus(200)->withHeader('Content-Type', 'application/json')->withBody(new SwooleStream(Json::encode([
                'code' => $throwable->getCode(),
                'message' => $throwable->getMessage()
            ])));
        }
        return $response;
    }


    public function isValid(Throwable $throwable):bool
    {
        return true;
    }
}