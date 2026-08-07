<?php

declare(strict_types=1);

/**
 * Standalone PSR-4 autoloader for running tests without Composer.
 * Used only by the test bootstrap; real apps use Composer's autoloader.
 */

// PSR-16 stub: tests use ArrayCache which implements this interface.
if (! interface_exists(\Psr\SimpleCache\CacheInterface::class)) {
    require __DIR__ . '/tests/Support/Psr16Stub.php';
}

spl_autoload_register(static function (string $class): void {
    // Test classes: HyperfExt\Jwt\Tests\* -> tests/
    $testsPrefix = 'HyperfExt\\Jwt\\Tests\\';
    if (str_starts_with($class, $testsPrefix)) {
        $relative = substr($class, strlen($testsPrefix));
        $file = __DIR__ . '/tests/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($file)) {
            require $file;
        }

        return;
    }

    // Production classes: HyperfExt\Jwt\* -> src/
    $prefix = 'HyperfExt\\Jwt\\';
    if (str_starts_with($class, $prefix)) {
        $relative = substr($class, strlen($prefix));
        $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
