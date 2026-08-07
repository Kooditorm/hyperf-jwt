<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

class RS512 extends AbstractRsa
{
    public function getAlgorithm(): string
    {
        return 'RS512';
    }

    protected function getOpensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
