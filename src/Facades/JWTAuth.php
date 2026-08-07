<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Facades;

use Hyperf\Framework\Facade;
use Kooditorm\Hyperf\Jwt\JWTAuth;

/**
 * @method static string fromSubject(\Kooditorm\Hyperf\Jwt\Contracts\JWTSubject $subject)
 * @method static string fromUser(\Kooditorm\Hyperf\Jwt\Contracts\JWTSubject $user)
 * @method static string refresh(bool $forceForever = false, bool $resetClaims = false)
 * @method static static invalidate(bool $forceForever = false)
 * @method static \Kooditorm\Hyperf\Jwt\Payload checkOrFail()
 * @method static \Kooditorm\Hyperf\Jwt\Payload|bool check(bool $getPayload = false)
 * @method static ?\Kooditorm\Hyperf\Jwt\Token getToken()
 * @method static static parseToken()
 * @method static \Kooditorm\Hyperf\Jwt\Payload getPayload()
 * @method static \Kooditorm\Hyperf\Jwt\Payload payload()
 * @method static mixed getClaim(string $claim)
 * @method static \Kooditorm\Hyperf\Jwt\Contracts\JWTSubject|false authenticate()
 * @method static false|string attempt(array $credentials)
 * @method static ?\Kooditorm\Hyperf\Jwt\Contracts\JWTSubject user()
 * @method static static setToken(\Kooditorm\Hyperf\Jwt\Token|string $token)
 * @method static static unsetToken()
 * @method static static setRequest(\Psr\Http\Message\ServerRequestInterface $request)
 * @method static static lockSubject(bool $lock)
 * @method static \Kooditorm\Hyperf\Jwt\Manager manager()
 * @method static \Kooditorm\Hyperf\Jwt\Http\Parser\Parser parser()
 * @method static \Kooditorm\Hyperf\Jwt\Factory factory()
 * @method static \Kooditorm\Hyperf\Jwt\Blacklist blacklist()
 */
class JWTAuthFacade extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return JWTAuth::class;
    }
}
