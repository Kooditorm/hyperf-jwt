<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Support;

use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use JsonException;

/**
 * JSON helpers that throw domain exceptions instead of returning null/false.
 */
class Json
{
    public static function encode(mixed $data): string
    {
        try {
            return json_encode(
                $data,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new TokenInvalidException(sprintf('Failed to JSON encode: %s', $e->getMessage()), 0, $e);
        }
    }

    public static function decode(string $json): mixed
    {
        try {
            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new TokenInvalidException(sprintf('Failed to JSON decode: %s', $e->getMessage()), 0, $e);
        }
    }
}
