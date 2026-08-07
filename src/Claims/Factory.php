<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Contracts\ClaimInterface;

/**
 * Builds the full set of claims for a token, merging sensible defaults
 * (iat, exp, nbf, jti, optional iss/aud) with any user-supplied claims.
 */
class Factory
{
    /**
     * Mapping of registered-claim name => claim class.
     */
    protected array $classMap = [
        'iss' => Issuer::class,
        'sub' => Subject::class,
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'nbf' => NotBefore::class,
        'iat' => IssuedAt::class,
        'jti' => JwtId::class,
    ];

    /**
     * Default claim configuration from the active scene.
     *
     * @var array{iss?: string|null, aud?: mixed, exp?: int, nbf?: int, jti?: bool}
     */
    protected array $config;

    protected int $leeway;

    /**
     * @param array $claimsConfig Scene `claims` config block
     * @param int   $leeway       Clock-skew tolerance in seconds
     */
    public function __construct(array $claimsConfig, int $leeway = 0)
    {
        $this->config = $claimsConfig;
        $this->leeway = $leeway;
    }

    /**
     * Build the complete claim set.
     *
     * @param array<string,mixed|ClaimInterface> $customClaims
     *
     * @return array<string,AbstractClaim>
     */
    public function build(array $customClaims = []): array
    {
        $claims = $this->buildDefaultClaims();

        foreach ($customClaims as $name => $value) {
            $claims[$name] = $this->normalize($name, $value);
        }

        return $claims;
    }

    /**
     * Instantiate a claim object for a name/value pair.
     */
    public function make(string $name, mixed $value): AbstractClaim
    {
        return $this->normalize($name, $value);
    }

    /**
     * Produce the default registered claims based on the scene config.
     *
     * @return array<string,AbstractClaim>
     */
    protected function buildDefaultClaims(): array
    {
        $now = time();
        $claims = [];

        // iat - always set to now.
        $claims['iat'] = $this->normalize('iat', $now);

        // exp - config is a TTL in seconds relative to now.
        $expTtl = (int) ($this->config['exp'] ?? 3600);
        if ($expTtl > 0) {
            $claims['exp'] = $this->normalize('exp', $now + $expTtl);
        }

        // nbf - config is a delay in seconds relative to now.
        $nbfDelay = (int) ($this->config['nbf'] ?? 0);
        if ($nbfDelay > 0) {
            $claims['nbf'] = $this->normalize('nbf', $now + $nbfDelay);
        }

        // iss - optional issuer.
        if (($this->config['iss'] ?? null) !== null) {
            $claims['iss'] = $this->normalize('iss', $this->config['iss']);
        }

        // aud - optional audience.
        if (($this->config['aud'] ?? null) !== null) {
            $claims['aud'] = $this->normalize('aud', $this->config['aud']);
        }

        // jti - unique token id (used for blacklisting).
        if ($this->config['jti'] ?? true) {
            $claims['jti'] = $this->normalize('jti', $this->generateJti());
        }

        return $claims;
    }

    /**
     * Normalize a raw value (or existing claim) into a configured claim instance.
     */
    protected function normalize(string $name, mixed $value): AbstractClaim
    {
        if ($value instanceof AbstractClaim) {
            return $value->withLeeway($this->leeway);
        }

        if ($value instanceof ClaimInterface && $value instanceof AbstractClaim === false) {
            // Exotic custom claim implementations: wrap into Custom.
            return (new Custom($name, $value->getValue()))->withLeeway($this->leeway);
        }

        $class = $this->classMap[$name] ?? Custom::class;

        if ($class === Custom::class) {
            $claim = new Custom($name, $value);
        } else {
            $claim = new $class($value);
        }

        return $claim->withLeeway($this->leeway);
    }

    /**
     * Generate a cryptographically-unique token id.
     */
    protected function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Update the leeway (used when scene config changes at runtime).
     */
    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Update the claim configuration at runtime (used by PayloadFactory).
     *
     * @param array $claimsConfig
     */
    public function setClaimConfig(array $claimsConfig): static
    {
        $this->config = $claimsConfig;

        return $this;
    }

    /**
     * Get the current claim configuration.
     */
    public function getClaimConfig(): array
    {
        return $this->config;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }
}
