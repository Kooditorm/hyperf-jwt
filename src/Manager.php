<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use function Hyperf\Collection\collect;

use Kooditorm\Hyperf\Jwt\Contracts\Providers\JWT as JWTContract;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenBlacklistedException;
use Kooditorm\Hyperf\Jwt\Support\CustomClaims;
use Kooditorm\Hyperf\Jwt\Support\RefreshFlow;

class Manager
{
    use CustomClaims;
    use RefreshFlow;

    protected JWTContract $provider;

    protected Blacklist $blacklist;

    protected Factory $payloadFactory;

    protected bool $blacklistEnabled = true;

    protected array $persistentClaims = [];

    public function __construct(JWTContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
            ->setRefreshFlow($this->refreshFlow)
            ->customClaims($payloadArray)
            ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     */
    public function refresh(Token $token, bool $forceForever = false, bool $resetClaims = false): Token
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            $this->invalidate($token, $forceForever);
        }

        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     */
    public function invalidate(Token $token, bool $forceForever = false): bool
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     */
    protected function buildRefreshClaims(Payload $payload): array
    {
        // Get the claims to be persisted from the payload
        $persistentClaims = collect($payload->toArray())
            ->only($this->persistentClaims)
            ->toArray();

        // Persist the relevant claims
        return array_merge(
            $this->customClaims,
            $persistentClaims,
            [
                'sub' => $payload['sub'],
                'iat' => $payload['iat'],
            ]
        );
    }

    public function getPayloadFactory(): Factory
    {
        return $this->payloadFactory;
    }

    public function getJWTProvider(): JWTContract
    {
        return $this->provider;
    }

    public function getBlacklist(): Blacklist
    {
        return $this->blacklist;
    }

    public function setBlacklistEnabled(bool $enabled): static
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    public function isBlacklistEnabled(): bool
    {
        return $this->blacklistEnabled;
    }

    public function setPersistentClaims(array $claims): static
    {
        $this->persistentClaims = $claims;

        return $this;
    }

    public function getPersistentClaims(): array
    {
        return $this->persistentClaims;
    }
}
