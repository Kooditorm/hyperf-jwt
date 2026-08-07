<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts\Providers;

interface JWT
{
    /**
     * Encode a payload array into a JWT string.
     */
    public function encode(array $payload): string;

    /**
     * Decode a JWT string into a payload array.
     */
    public function decode(string $token): array;
}
