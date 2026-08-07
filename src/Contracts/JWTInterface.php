<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Contracts;

use HyperfExt\Jwt\Payload\Payload;
use HyperfExt\Jwt\Token;

/**
 * The high-level JWT service: issue, parse, verify, refresh and revoke tokens.
 *
 * Mirrors tymon/jwt-auth's JWTAuth contract — operates on Token / Payload
 * value objects rather than raw strings.
 */
interface JWTInterface
{
    /**
     * Encode a Payload into a signed Token.
     */
    public function encode(Payload $payload): Token;

    /**
     * Encode an array of custom claims into a Token (convenience).
     *
     * @param array<string,mixed> $customClaims
     */
    public function encodeFromClaims(array $customClaims = []): Token;

    /**
     * Decode and verify a Token, returning the validated Payload.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenInvalidException
     * @throws \HyperfExt\Jwt\Exceptions\TokenExpiredException
     * @throws \HyperfExt\Jwt\Exceptions\TokenBlacklistedException
     */
    public function decode(Token|string $token): Payload;

    /**
     * Issue a fresh Token for an existing (still-refreshable) Token.
     *
     * When $token is null, implementations may resolve from internal state.
     */
    public function refresh(Token|string|null $token = null): Token;

    /**
     * Revoke a Token by adding it to the blacklist.
     *
     * When $token is null, implementations may resolve from internal state.
     */
    public function invalidate(Token|string|null $token = null): bool;

    /**
     * Verify a Token's signature and claims without throwing.
     */
    public function validate(Token|string $token): bool;

    /**
     * Get the token Payload without full validation checks (signature only).
     */
    public function payload(Token|string $token): Payload;

    /**
     * Create a Token from a JWTSubject (user model).
     */
    public function fromSubject(JWTSubject $subject): Token;

    /**
     * Parse a token from a raw Authorization header string.
     */
    public function parseToken(?string $bearer = null): static|false;

    /**
     * Set the token to operate on (chainable).
     */
    public function setToken(Token|string $token): static;
}
