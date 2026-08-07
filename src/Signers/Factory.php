<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

use HyperfExt\Jwt\Contracts\SignerInterface;
use HyperfExt\Jwt\Exceptions\JWTException;

/**
 * Resolves a signer instance from a scene's algorithm + key configuration.
 */
class Factory
{
    /**
     * Algorithm => signer class mapping.
     */
    protected array $algos = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
    ];

    /**
     * Build a signer for the given algorithm and key material.
     *
     * @param string      $algo   Algorithm name (case-insensitive)
     * @param string      $secret HMAC shared secret
     * @param string|null $public Public key PEM (asymmetric algos)
     * @param string|null $private Private key PEM (asymmetric algos)
     * @param string|null $passphrase Private key passphrase
     */
    public function create(
        string $algo,
        string $secret = '',
        ?string $public = null,
        ?string $private = null,
        ?string $passphrase = null
    ): SignerInterface {
        $class = $this->algos[strtoupper($algo)] ?? null;

        if ($class === null) {
            throw new JWTException(sprintf('Unsupported JWT algorithm: %s', $algo));
        }

        return new $class($secret, $public, $private, $passphrase);
    }

    /**
     * Whether the given algorithm is supported.
     */
    public function supports(string $algo): bool
    {
        return isset($this->algos[strtoupper($algo)]);
    }

    /**
     * Register a custom algorithm mapping.
     */
    public function extend(string $algo, string $className): static
    {
        $this->algos[strtoupper($algo)] = $className;

        return $this;
    }
}
