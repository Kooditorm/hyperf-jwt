<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

class RS384 extends AbstractRsa
{
    public function getAlgorithm(): string
    {
        return 'RS384';
    }

    protected function getOpensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
}
