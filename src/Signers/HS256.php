<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

class HS256 extends AbstractHmac
{
    public function getAlgorithm(): string
    {
        return 'HS256';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }
}
