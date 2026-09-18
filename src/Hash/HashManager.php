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

use Hyperf\Contract\ConfigInterface;
use InvalidArgumentException;
use Kooditorm\Hyperf\Hash\Contract\DriverInterface;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;
use function Hyperf\Support\make;

class HashManager implements HashInterface
{
    /**
     * The array of created "drivers".
     *
     * @var array<string, DriverInterface>
     */
    protected array $drivers = [];

    public function __construct(protected readonly ConfigInterface $config)
    {
    }

    /**
     * Get information about the given hashed value.
     */
    public function info(string $hashedValue): array
    {
        return $this->getDriver()->info($hashedValue);
    }

    /**
     * Hash the given value.
     */
    public function make(string $value, array $options = []): string
    {
        return $this->getDriver()->make($value, $options);
    }

    /**
     * Check the given plain value against a hash.
     */
    public function check(string $value, string $hashedValue, array $options = []): bool
    {
        return $this->getDriver()->check($value, $hashedValue, $options);
    }

    /**
     * Check if the given hash has been hashed using the given options.
     */
    public function needsRehash(string $hashedValue, array $options = []): bool
    {
        return $this->getDriver()->needsRehash($hashedValue, $options);
    }

    /**
     * Get a driver instance.
     *
     * @throws InvalidArgumentException
     */
    public function getDriver(?string $name = null): DriverInterface
    {
        $name = $name ?: $this->config->get('hash.default', 'bcrypt');

        if (isset($this->drivers[$name])) {
            return $this->drivers[$name];
        }

        $config = $this->config->get("hash.driver.{$name}");
        if (empty($config['class'])) {
            throw new InvalidArgumentException(sprintf('The hash driver config %s is invalid.', $name));
        }

        $driver = make($config['class'], ['options' => $config['options'] ?? []]);

        return $this->drivers[$name] = $driver;
    }
}
