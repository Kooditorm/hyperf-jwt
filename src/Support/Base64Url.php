<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Support;

use HyperfExt\Jwt\Exceptions\TokenInvalidException;

/**
 * Base64url encoding/decoding per RFC 7515 (no padding).
 */
class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new TokenInvalidException('Could not decode base64url string.');
        }

        return $decoded;
    }
}
