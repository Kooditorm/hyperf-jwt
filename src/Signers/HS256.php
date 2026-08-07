<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Signers;

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
