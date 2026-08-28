<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Hash;


use Hyperf\Context\ApplicationContext;
use Kooditorm\Hyperf\Hash\Contract\DriverInterface;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;

abstract class Hash
{
    public static function getDriver(?string $name = null): DriverInterface
    {
        return ApplicationContext::getContainer()->get(HashInterface::class)->getDriver($name);
    }

    public static function info(string $hashedValue, ?string $driverName = null): array
    {
        return static::getDriver($driverName)->info($hashedValue);
    }

    public static function make(string $value, array $options = [], ?string $driverName = null): string
    {
        return static::getDriver($driverName)->make($value, $options);
    }

    public static function check(string $value, string $hashedValue, array $options = [], ?string $driverName = null): bool
    {
        return static::getDriver($driverName)->check($value, $hashedValue, $options);
    }

    public static function needsRehash(string $hashedValue, array $options = [], ?string $driverName = null): bool
    {
        return static::getDriver($driverName)->needsRehash($hashedValue, $options);
    }
}