<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Contracts\JWTSubject;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth;
use Kooditorm\Hyperf\Jwt\Http\Parser\Parser;

/**
 * JWT with authentication capabilities.
 */
class JWTAuth extends JWT
{
    protected Auth $auth;

    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     */
    public function attempt(array $credentials): false|string
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     */
    public function authenticate(): JWTSubject|false
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     */
    public function toUser(): JWTSubject|false
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     */
    public function user(): ?JWTSubject
    {
        return $this->auth->user();
    }
}
