<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

class HS512 extends AbstractHmac
{
    public function getAlgorithm(): string
    {
        return 'HS512';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }
}
