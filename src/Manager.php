<?php

declare(strict_types=1);

namespace HyperfExt\Jwt;

use HyperfExt\Jwt\Blacklist\Blacklist;
use HyperfExt\Jwt\Contracts\JWTProvider;
use HyperfExt\Jwt\Exceptions\JWTException;
use HyperfExt\Jwt\Exceptions\TokenBlacklistedException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use HyperfExt\Jwt\Payload\Payload;
use HyperfExt\Jwt\Payload\PayloadValidator;

/**
 * Core JWT engine — encode, decode, refresh, invalidate.
 *
 * This is the HyperfExt equivalent of tymon/jwt-auth's Manager. It operates
 * purely on Token / Payload value objects and is unaware of HTTP requests,
 * users, or the framework's auth system. The higher-level {@see JWT} class
 * extends this to add request parsing and subject authentication.
 *
 * Dependencies:
 *  - {@see JWTProvider}       low-level encode / decode (signing + base64url)
 *  - {@see PayloadFactory}     builds Payload objects (default + custom claims)
 *  - {@see Blacklist}          token revocation storage
 *  - {@see PayloadValidator}   claim-level validation (exp / nbf / iss / aud)
 */
class Manager
{
    /**
     * Scene configuration (algo, leeway, refresh_ttl, ...).
     */
    protected array $config;

    public function __construct(
        protected JWTProvider $provider,
        protected PayloadFactory $payloadFactory,
        protected PayloadValidator $validator,
        protected ?Blacklist $blacklist,
        array $config
    ) {
        $this->setConfig($config);
    }

    /**
     * Replace the scene configuration at runtime.
     *
     * Propagates leeway, expected claims, and blacklist settings to all
     * sub-components. The JWTProvider's signer is re-resolved lazily.
     */
    public function setConfig(array $config): static
    {
        $this->config = $config;

        // Sync leeway + expected claims to the validator and payload factory.
        $leeway = (int) ($config['leeway'] ?? 0);
        $this->payloadFactory->getClaimFactory()->setLeeway($leeway);
        $this->validator->setLeeway($leeway);
        $this->validator->setExpectedClaims($config['claims'] ?? []);

        // Sync claim config to the payload factory.
        $this->payloadFactory->setClaimConfig($config['claims'] ?? []);

        // Propagate blacklist settings.
        if ($this->blacklist) {
            $this->blacklist
                ->setEnabled((bool) ($config['blacklist_enabled'] ?? true))
                ->setGracePeriod((int) ($config['blacklist_grace_period'] ?? 0))
                ->setStorageTtl((int) ($config['blacklist_storage_ttl'] ?? 20160));
        }

        // Sync config to the JWT provider (forces signer re-resolution).
        if ($this->provider instanceof Providers\NativeJwtProvider) {
            $this->provider->setConfig($config);
        }

        return $this;
    }

    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Encode a Payload into a signed Token.
     */
    public function encode(Payload $payload): Token
    {
        $token = $this->provider->encode($payload->toArray());

        return new Token($token);
    }

    /**
     * Encode an array of custom claims into a Token (convenience).
     *
     * @param array<string,mixed> $customClaims
     */
    public function encodeFromClaims(array $customClaims = []): Token
    {
        $payload = $this->payloadFactory->make($customClaims);

        return $this->encode($payload);
    }

    /**
     * Decode and verify a Token, returning the validated Payload.
     *
     * @throws TokenInvalidException     malformed token / bad signature
     * @throws TokenBlacklistedException token has been revoked
     */
    public function decode(Token|string $token): Payload
    {
        $token = Token::from($token);

        $payloadData = $this->provider->decode($token->get());

        $payload = $this->payloadFactory->makeFromRaw($payloadData);

        $this->validator->validate($payload);

        $this->checkBlacklist($payload);

        return $payload;
    }

    /**
     * Issue a fresh Token for an existing (still-refreshable) Token.
     *
     * The old token is added to the blacklist. Custom claims are carried over;
     * registered time-claims (iat / exp / nbf / jti) are regenerated.
     *
     * When $token is null, subclasses (e.g. JWT) may resolve it from internal state.
     */
    public function refresh(Token|string|null $token = null): Token
    {
        $token = Token::from($token ?? throw new JWTException('No token provided for refresh.'));

        // Refresh allows an expired token: only verify the signature.
        $payloadData = $this->provider->decode($token->get());
        $payload = $this->payloadFactory->makeFromRaw($payloadData);

        // Enforce the refresh window based on iat.
        if ($payload->has('iat')) {
            $iat = (int) $payload->value('iat');
            $refreshTtl = ((int) ($this->config['refresh_ttl'] ?? 20160)) * 60;

            if ($iat + $refreshTtl < time()) {
                throw new TokenInvalidException('Token can no longer be refreshed; refresh_ttl exceeded.');
            }
        }

        // Blacklist the old token before issuing a new one.
        if ($this->blacklist?->isEnabled()) {
            $this->blacklist->add($payload);
        }

        // Carry over custom claims, drop time-sensitive registered ones.
        $customClaims = [];
        foreach ($payload->toArray() as $name => $value) {
            if (! in_array($name, ['iat', 'exp', 'nbf', 'jti'], true)) {
                $customClaims[$name] = $value;
            }
        }

        return $this->encodeFromClaims($customClaims);
    }

    /**
     * Revoke a Token by adding it to the blacklist.
     *
     * An expired token may still be invalidated (only the signature is verified).
     *
     * When $token is null, subclasses (e.g. JWT) may resolve it from internal state.
     */
    public function invalidate(Token|string|null $token = null): bool
    {
        if (! $this->blacklist?->isEnabled()) {
            throw new JWTException('Blacklist is disabled; cannot invalidate token.');
        }

        $token = Token::from($token ?? throw new JWTException('No token provided for invalidation.'));

        $payloadData = $this->provider->decode($token->get());
        $payload = $this->payloadFactory->makeFromRaw($payloadData);

        return $this->blacklist->add($payload);
    }

    /**
     * Verify a Token without throwing. Returns true on success.
     */
    public function validate(Token|string $token): bool
    {
        try {
            $this->decode($token);

            return true;
        } catch (JWTException $e) {
            return false;
        }
    }

    /**
     * Get the token payload (claims) without full validation checks.
     *
     * Only the signature is verified; exp / nbf / iss / aud are NOT checked.
     */
    public function payload(Token|string $token): Payload
    {
        $payloadData = $this->provider->decode(Token::from($token)->get());

        return $this->payloadFactory->makeFromRaw($payloadData);
    }

    /**
     * Reject blacklisted tokens.
     */
    protected function checkBlacklist(Payload $payload): void
    {
        if (! $this->blacklist?->isEnabled()) {
            return;
        }

        if ($this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('Token has been blacklisted.');
        }
    }

    public function getProvider(): JWTProvider
    {
        return $this->provider;
    }

    public function getPayloadFactory(): PayloadFactory
    {
        return $this->payloadFactory;
    }

    public function getValidator(): PayloadValidator
    {
        return $this->validator;
    }

    public function getBlacklist(): ?Blacklist
    {
        return $this->blacklist;
    }
}
