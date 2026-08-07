<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

class HS384 extends AbstractHmac
{
    public function getAlgorithm(): string
    {
        return 'HS384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }
}
