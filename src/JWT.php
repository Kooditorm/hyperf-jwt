<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use BadMethodCallException;
use Hyperf\Context\Context;
use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\JWTSubject;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Http\Parser\Parser;
use Kooditorm\Hyperf\Jwt\Support\CustomClaims;

class JWT
{
    use CustomClaims;

    protected Manager $manager;

    protected Parser $parser;

    protected bool $lockSubject = true;

    /**
     * Context key for storing the current token (coroutine-safe).
     */
    protected string $tokenContextKey = 'kooditorm.jwt.token';

    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     */
    public function fromSubject(JWTSubject $subject): string
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     */
    public function fromUser(JWTSubject $user): string
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     */
    public function refresh(bool $forceForever = false, bool $resetClaims = false): string
    {
        $this->requireToken();

        return $this->manager
            ->customClaims($this->getCustomClaims())
            ->refresh($this->token(), $forceForever, $resetClaims)
            ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     */
    public function invalidate(bool $forceForever = false): static
    {
        $this->requireToken();

        $this->manager->invalidate($this->token(), $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     */
    public function checkOrFail(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     */
    public function check(bool $getPayload = false): Payload|bool
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     */
    public function getToken(): ?Token
    {
        $token = Context::get($this->tokenContextKey);

        if ($token === null) {
            try {
                $this->parseToken();
            } catch (JWTException) {
                Context::set($this->tokenContextKey, null);
            }
        }

        return Context::get($this->tokenContextKey);
    }

    /**
     * Parse the token from the request.
     */
    public function parseToken(): static
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     */
    public function getPayload(): Payload
    {
        $this->requireToken();

        return $this->manager->decode($this->token());
    }

    /**
     * Alias for getPayload().
     */
    public function payload(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     */
    public function getClaim(string $claim): mixed
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     */
    public function makePayload(JWTSubject $subject): Payload
    {
        return $this->factory()
            ->customClaims($this->getClaimsArray($subject))
            ->make();
    }

    /**
     * Build the claims array and return it.
     */
    protected function getClaimsArray(JWTSubject $subject): array
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(),
            $this->customClaims
        );
    }

    protected function getClaimsForSubject(JWTSubject $subject): array
    {
        $claims = ['sub' => $subject->getJWTIdentifier()];

        if ($this->lockSubject) {
            $claims['prv'] = $this->hashSubjectModel($subject);
        }

        return $claims;
    }

    protected function hashSubjectModel(object|string $model): string
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     */
    public function checkSubjectModel(object|string $model): bool
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
    }

    /**
     * Set the token (stored in coroutine context for safety).
     */
    public function setToken(Token|string $token): static
    {
        $token = $token instanceof Token ? $token : new Token($token);
        Context::set($this->tokenContextKey, $token);

        return $this;
    }

    /**
     * Unset the current token.
     */
    public function unsetToken(): static
    {
        Context::set($this->tokenContextKey, null);

        return $this;
    }

    protected function requireToken(): void
    {
        if (! Context::get($this->tokenContextKey)) {
            throw new JWTException('A token is required');
        }
    }

    /**
     * Get the current token from context.
     */
    protected function token(): Token
    {
        return Context::get($this->tokenContextKey);
    }

    /**
     * Set the request instance for the parser.
     */
    public function setRequest(ServerRequestInterface $request): static
    {
        $this->parser->setRequest($request);

        return $this;
    }

    public function lockSubject(bool $lock): static
    {
        $this->lockSubject = $lock;

        return $this;
    }

    public function isLockSubject(): bool
    {
        return $this->lockSubject;
    }

    public function manager(): Manager
    {
        return $this->manager;
    }

    public function parser(): Parser
    {
        return $this->parser;
    }

    public function factory(): Factory
    {
        return $this->manager->getPayloadFactory();
    }

    public function blacklist(): Blacklist
    {
        return $this->manager->getBlacklist();
    }

    public function __call(string $method, array $parameters): mixed
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [{$method}] does not exist.");
    }
}
