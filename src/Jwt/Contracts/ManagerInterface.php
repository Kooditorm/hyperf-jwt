<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Contracts;

use Kooditorm\Hyperf\Jwt\Payload;
use Kooditorm\Hyperf\Jwt\Token;
interface ManagerInterface
{
    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token;

    /**
     * Decode a Token and return the Payload.
     *
     * @throws \Kooditorm\Hyperf\Jwt\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload;

    /**
     * Refresh a Token and return a new Token.
     *
     * @throws \Kooditorm\Hyperf\Jwt\Exceptions\TokenBlacklistedException
     * @throws \Kooditorm\Hyperf\Jwt\Exceptions\JwtException
     */
    public function refresh(Token $token, bool $forceForever = false): Token;

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws \Kooditorm\Hyperf\Jwt\Exceptions\JwtException
     */
    public function invalidate(Token $token, bool $forceForever = false): bool;
}