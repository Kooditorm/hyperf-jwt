<?php

declare(strict_types=1);

namespace HyperfExt\Jwt;

use HyperfExt\Jwt\Contracts\JWTSubject;
use HyperfExt\Jwt\Payload\Payload;
use HyperfExt\Jwt\Token;

/**
 * Multi-scene JWT manager.
 *
 * Resolves and caches a {@see JWT} instance per scene so that each request
 * only pays the configuration cost once. Also provides pass-through
 * convenience methods that delegate to the default scene — mirroring the
 * "single-instance" feel of tymon/jwt-auth while supporting multiple scenes.
 */
class JwtManager
{
    /**
     * @var array<string,JWT>
     */
    protected array $instances = [];

    public function __construct(protected JwtFactory $factory)
    {
    }

    /**
     * Get (and cache) the JWT instance for a scene.
     */
    public function scene(?string $name = null): JWT
    {
        // Use a sentinel so that `null` (default scene) caches distinctly.
        $key = $name ?? '__default__';

        return $this->instances[$key] ??= $this->factory->make($name);
    }

    /**
     * Convenience: get the default-scene JWT.
     */
    public function default(): JWT
    {
        return $this->scene(null);
    }

    /**
     * Forget a cached scene (forces re-creation on next access).
     */
    public function forget(?string $name = null): static
    {
        $key = $name ?? '__default__';
        unset($this->instances[$key]);

        return $this;
    }

    // ─── Pass-through convenience methods (default scene) ───────────────────

    /**
     * Encode a Payload into a Token using the default scene.
     */
    public function encode(Payload $payload): Token
    {
        return $this->default()->encode($payload);
    }

    /**
     * Encode custom claims into a Token using the default scene.
     *
     * @param array<string,mixed> $customClaims
     */
    public function encodeFromClaims(array $customClaims = []): Token
    {
        return $this->default()->encodeFromClaims($customClaims);
    }

    /**
     * Create a Token from a JWTSubject using the default scene.
     */
    public function fromSubject(JWTSubject $subject): Token
    {
        return $this->default()->fromSubject($subject);
    }

    /**
     * Decode a Token using the default scene.
     */
    public function decode(Token|string $token): Payload
    {
        return $this->default()->decode($token);
    }

    /**
     * Refresh a Token using the default scene.
     */
    public function refresh(Token|string $token): Token
    {
        return $this->default()->refresh($token);
    }

    /**
     * Invalidate a Token using the default scene.
     */
    public function invalidate(Token|string $token): bool
    {
        return $this->default()->invalidate($token);
    }

    /**
     * Validate a Token using the default scene.
     */
    public function validate(Token|string $token): bool
    {
        return $this->default()->validate($token);
    }
}
