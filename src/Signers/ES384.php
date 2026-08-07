<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

class ES384 extends AbstractEcdsa
{
    public function getAlgorithm(): string
    {
        return 'ES384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getSignatureLength(): int
    {
        return 48;
    }
}
