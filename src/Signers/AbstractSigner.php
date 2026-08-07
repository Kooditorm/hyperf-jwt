<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

use HyperfExt\Jwt\Contracts\SignerInterface;
use HyperfExt\Jwt\Exceptions\JWTException;

/**
 * Shared key material for all signers.
 */
abstract class AbstractSigner implements SignerInterface
{
    /**
     * HMAC shared secret (for HS* algorithms).
     */
    protected string $secret = '';

    /**
     * Asymmetric public key PEM (for RS256/ES256 verification).
     */
    protected ?string $publicKey = null;

    /**
     * Asymmetric private key PEM (for RS256/ES256 signing).
     */
    protected ?string $privateKey = null;

    /**
     * Passphrase for an encrypted private key.
     */
    protected ?string $passphrase = null;

    public function __construct(
        string $secret = '',
        ?string $publicKey = null,
        ?string $privateKey = null,
        ?string $passphrase = null
    ) {
        $this->secret = $secret;
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->passphrase = $passphrase;
    }

    public function isAsymmetric(): bool
    {
        return $this->publicKey !== null || $this->privateKey !== null;
    }

    /**
     * Ensure the shared secret is available for HMAC signing.
     */
    protected function requireSecret(): string
    {
        if ($this->secret === '') {
            throw new JWTException(
                sprintf('A non-empty secret is required for the %s algorithm.', $this->getAlgorithm())
            );
        }

        return $this->secret;
    }

    /**
     * Load a private key resource, throwing on failure.
     *
     * @return \OpenSSLAsymmetricKey
     */
    protected function requirePrivateKey(): mixed
    {
        if ($this->privateKey === null || $this->privateKey === '') {
            throw new JWTException(
                sprintf('A private key is required to sign with the %s algorithm.', $this->getAlgorithm())
            );
        }

        $key = openssl_pkey_get_private($this->privateKey, $this->passphrase ?? '');

        if (! $key) {
            throw new JWTException(
                sprintf('Failed to load the private key for %s: %s', $this->getAlgorithm(), openssl_error_string() ?: 'unknown error')
            );
        }

        return $key;
    }

    /**
     * Load a public key resource, throwing on failure.
     *
     * @return \OpenSSLAsymmetricKey
     */
    protected function requirePublicKey(): mixed
    {
        if ($this->publicKey === null || $this->publicKey === '') {
            throw new JWTException(
                sprintf('A public key is required to verify with the %s algorithm.', $this->getAlgorithm())
            );
        }

        $key = openssl_pkey_get_public($this->publicKey);

        if (! $key) {
            throw new JWTException(
                sprintf('Failed to load the public key for %s: %s', $this->getAlgorithm(), openssl_error_string() ?: 'unknown error')
            );
        }

        return $key;
    }
}
