<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Support;

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time (UTC).
     */
    public static function now(): Carbon
    {
        return Carbon::now('UTC');
    }

    /**
     * Get the Carbon instance for the given timestamp.
     */
    public static function timestamp(int $timestamp): Carbon
    {
        return Carbon::createFromTimestampUTC($timestamp)->timezone('UTC');
    }

    /**
     * Checks if a timestamp is in the past.
     */
    public static function isPast(int $timestamp, int $leeway = 0): bool
    {
        $timestamp = static::timestamp($timestamp);

        return $leeway > 0
            ? $timestamp->addSeconds($leeway)->isPast()
            : $timestamp->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     */
    public static function isFuture(int $timestamp, int $leeway = 0): bool
    {
        $timestamp = static::timestamp($timestamp);

        return $leeway > 0
            ? $timestamp->subSeconds($leeway)->isFuture()
            : $timestamp->isFuture();
    }

    /**
     * Get the difference in minutes between the given timestamp and now.
     * Returns a positive integer (ceiling).
     */
    public static function minutesUntil(int $timestamp): int
    {
        $expiration = static::timestamp($timestamp);
        $minutes = method_exists($expiration, 'diffInRealMinutes')
            ? $expiration->diffInRealMinutes()
            : (method_exists($expiration, 'diffInUTCMinutes')
                ? $expiration->diffInUTCMinutes()
                : $expiration->diffInMinutes());

        return (int) ceil(abs($minutes));
    }
}
