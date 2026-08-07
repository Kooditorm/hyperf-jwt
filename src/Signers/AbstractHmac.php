<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

/**
 * HMAC signer base (HS256 / HS384 / HS512). Uses a shared secret.
 */
abstract class AbstractHmac extends AbstractSigner
{
    public function sign(string $payload): string
    {
        return hash_hmac($this->getHashAlgorithm(), $payload, $this->requireSecret(), true);
    }

    public function verify(string $expected, string $payload): bool
    {
        return hash_equals($this->sign($payload), $expected);
    }

    public function isAsymmetric(): bool
    {
        return false;
    }

    /**
     * The PHP hash algorithm name, e.g. `sha256`.
     */
    abstract protected function getHashAlgorithm(): string;
}
