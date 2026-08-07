<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Providers;

use HyperfExt\Jwt\Contracts\JWTProvider;
use HyperfExt\Jwt\Contracts\SignerInterface;
use HyperfExt\Jwt\Exceptions\SignatureInvalidException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use HyperfExt\Jwt\Signers\Factory as SignerFactory;
use HyperfExt\Jwt\Support\Base64Url;
use HyperfExt\Jwt\Support\Json;

/**
 * JWT engine backed by native PHP openssl / hash extensions.
 *
 * This is the HyperfExt equivalent of tymon/jwt-auth's Lcobucci provider —
 * it handles base64url serialisation, JSON marshalling, header construction
 * and signature creation / verification.
 *
 * One instance == one scene's signing configuration. The resolved signer is
 * cached lazily so repeated encode / decode calls on the same scene pay zero
 * factory overhead.
 */
class NativeJwtProvider implements JWTProvider
{
    protected ?SignerInterface $signer = null;

    /**
     * @param array{secret?:string,keys?:array{public?:?string,private?:?string,passphrase?:?string},algo?:string} $config
     */
    public function __construct(
        protected SignerFactory $signerFactory,
        protected array $config
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function encode(array $payload): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => strtoupper((string) ($this->config['algo'] ?? 'HS256')),
        ];

        $headerSegment = Base64Url::encode(Json::encode($header));
        $payloadSegment = Base64Url::encode(Json::encode($payload));

        $signingInput = $headerSegment . '.' . $payloadSegment;

        $signature = $this->getSigner()->sign($signingInput);

        return $signingInput . '.' . Base64Url::encode($signature);
    }

    /**
     * {@inheritDoc}
     */
    public function decode(string $token): array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            throw new TokenInvalidException('Wrong number of token segments; expected 3.');
        }

        [$headerB64, $payloadB64, $signatureB64] = $segments;

        $header = Json::decode(Base64Url::decode($headerB64));
        $payloadData = Json::decode(Base64Url::decode($payloadB64));
        $signature = Base64Url::decode($signatureB64);

        if (! is_array($header) || ! is_array($payloadData)) {
            throw new TokenInvalidException('Token header or payload is not a JSON object.');
        }

        $algo = $header['alg'] ?? null;
        $configuredAlgo = strtoupper((string) ($this->config['algo'] ?? 'HS256'));

        if ($algo !== $configuredAlgo) {
            throw new TokenInvalidException(sprintf(
                'Algorithm mismatch: token uses [%s] but scene is configured for [%s].',
                $algo ?? 'none',
                $configuredAlgo
            ));
        }

        $signingInput = $headerB64 . '.' . $payloadB64;

        if (! $this->getSigner()->verify($signature, $signingInput)) {
            throw new SignatureInvalidException('Token signature could not be verified.');
        }

        return $payloadData;
    }

    /**
     * Update the signing configuration at runtime (forces signer re-resolution).
     */
    public function setConfig(array $config): static
    {
        $this->config = $config;
        $this->signer = null;

        return $this;
    }

    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Lazily resolve and cache the signer for the current scene.
     */
    protected function getSigner(): SignerInterface
    {
        if ($this->signer instanceof SignerInterface) {
            return $this->signer;
        }

        $keys = $this->config['keys'] ?? [];

        $this->signer = $this->signerFactory->create(
            (string) ($this->config['algo'] ?? 'HS256'),
            (string) ($this->config['secret'] ?? ''),
            $keys['public'] ?? null,
            $keys['private'] ?? null,
            $keys['passphrase'] ?? null
        );

        return $this->signer;
    }
}
