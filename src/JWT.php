<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Contracts\JWTSubject;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Payload\Payload;

/**
 * High-level JWT service for a single scene.
 *
 * Extends {@see Manager} (the core engine) with request-parsing and
 * subject-authentication features — the HyperfExt equivalent of
 * tymon/jwt-auth's JWTAuth.
 *
 * One instance == one scene. Use {@see JwtManager} to obtain instances
 * for multiple scenes.
 *
 * Typical usage in a controller:
 *
 *     $jwt = $manager->scene('api');
 *     $token = $jwt->fromSubject($user);
 *     $payload = $jwt->parseToken()->getPayload();
 *     $user = $jwt->subject();
 */
class JWT extends Manager
{
    /**
     * The currently-parsed token (set by parseToken / setToken).
     */
    protected ?Token $token = null;

    /**
     * Callable that resolves a subject from a `sub` claim value.
     *
     * @var callable(mixed): ?JWTSubject
     */
    protected $subjectResolver = null;

    // ─── Subject-based token creation ───────────────────────────────────────

    /**
     * Create a Token from a JWTSubject (user model).
     *
     * The subject's identifier is stored in the `sub` claim, and any custom
     * claims returned by `getJWTCustomClaims()` are merged in.
     */
    public function fromSubject(JWTSubject $subject): Token
    {
        $customClaims = $subject->getJWTCustomClaims();
        $customClaims['sub'] = $subject->getJWTIdentifier();

        return $this->encodeFromClaims($customClaims);
    }

    /**
     * Alias for {@see fromSubject()}.
     */
    public function fromUser(JWTSubject $subject): Token
    {
        return $this->fromSubject($subject);
    }

    // ─── Subject resolution ─────────────────────────────────────────────────

    /**
     * Set the callable used to resolve a subject from the `sub` claim.
     *
     *     $jwt->setSubjectResolver(fn ($id) => UserRepository::find($id));
     */
    public function setSubjectResolver(callable $resolver): static
    {
        $this->subjectResolver = $resolver;

        return $this;
    }

    /**
     * Resolve and return the subject indicated by the current token.
     *
     * Requires that {@see setSubjectResolver()} has been called.
     */
    public function subject(): ?JWTSubject
    {
        if ($this->token === null) {
            throw new JWTException('A token must be set before resolving the subject.');
        }

        if ($this->subjectResolver === null) {
            throw new JWTException('No subject resolver has been configured.');
        }

        $payload = $this->decode($this->token);

        if (! $payload->has('sub')) {
            return null;
        }

        return ($this->subjectResolver)($payload->value('sub'));
    }

    /**
     * Alias for {@see subject()}.
     */
    public function user(): ?JWTSubject
    {
        return $this->subject();
    }

    // ─── Token state management ─────────────────────────────────────────────

    /**
     * Set the token to operate on (chainable).
     */
    public function setToken(Token|string $token): static
    {
        $this->token = Token::from($token);

        return $this;
    }

    /**
     * Get the currently-set Token, or null.
     */
    public function getToken(): ?Token
    {
        return $this->token;
    }

    /**
     * Get the Payload of the currently-set Token.
     */
    public function getPayload(): Payload
    {
        if ($this->token === null) {
            throw new JWTException('A token must be set before calling getPayload().');
        }

        return $this->decode($this->token);
    }

    // ─── Token parsing (request extraction) ────────────────────────────────

    /**
     * Parse the token from a raw header string or query parameter.
     *
     * Call this when you have the raw Authorization header value, e.g.:
     *
     *     $jwt->parseToken($request->getHeaderLine('Authorization'));
     *
     * Returns `$this` for chaining or false when no token is found.
     */
    public function parseToken(?string $bearer = null): static|false
    {
        $token = null;

        if ($bearer !== null && $bearer !== '') {
            // Accept "Bearer <token>" or a bare token string.
            if (preg_match('/Bearer\s+(.*)$/i', $bearer, $matches)) {
                $token = trim($matches[1]);
            } elseif (strpos($bearer, '.') !== false) {
                $token = trim($bearer);
            }
        }

        if ($token === null || $token === '') {
            return false;
        }

        return $this->setToken($token);
    }

    /**
     * Invalidate the currently-set or given token (convenience).
     */
    public function invalidate(Token|string|null $token = null): bool
    {
        $token ??= $this->token;

        if ($token === null) {
            throw new JWTException('No token to invalidate.');
        }

        return parent::invalidate($token);
    }

    /**
     * Refresh the currently-set or given token (convenience).
     */
    public function refresh(Token|string|null $token = null): Token
    {
        $token ??= $this->token;

        if ($token === null) {
            throw new JWTException('No token to refresh.');
        }

        return parent::refresh($token);
    }

    /**
     * Reset the token state (clears the internally-parsed token).
     */
    public function reset(): static
    {
        $this->token = null;

        return $this;
    }
}
