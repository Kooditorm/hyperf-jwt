<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

/**
 * RSA signer base (RS256 / RS384 / RS512). Uses a public/private key pair.
 */
abstract class AbstractRsa extends AbstractSigner
{
    public function sign(string $payload): string
    {
        $key = $this->requirePrivateKey();
        $signature = '';

        if (! openssl_sign($payload, $signature, $key, $this->getOpensslAlgorithm())) {
            throw new \HyperfExt\Jwt\Exceptions\JWTException(
                sprintf('OpenSSL failed to sign with %s: %s', $this->getAlgorithm(), openssl_error_string() ?: 'unknown error')
            );
        }

        return $signature;
    }

    public function verify(string $expected, string $payload): bool
    {
        $key = $this->requirePublicKey();

        return openssl_verify($payload, $expected, $key, $this->getOpensslAlgorithm()) === 1;
    }

    public function isAsymmetric(): bool
    {
        return true;
    }

    /**
     * The OpenSSL algorithm constant (e.g. OPENSSL_ALGO_SHA256).
     */
    abstract protected function getOpensslAlgorithm(): int;
}
