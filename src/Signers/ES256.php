<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

class ES256 extends AbstractEcdsa
{
    public function getAlgorithm(): string
    {
        return 'ES256';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function getSignatureLength(): int
    {
        return 32;
    }
}
