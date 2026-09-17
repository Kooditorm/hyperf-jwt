<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Access;

use Hyperf\Context\ApplicationContext;
use Kooditorm\Hyperf\Auth\Contracts\Access\GateManagerInterface;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

trait Authorizable
{
    /**
     * Determine if the entity has the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function can(iterable|string $abilities, mixed $arguments = []): bool
    {
        return $this->gateManager()
            ->forUser($this)
            ->check($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function cant(iterable|string $abilities, mixed $arguments = []): bool
    {
        return ! $this->can($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @param iterable|string $abilities
     * @param array|mixed $arguments
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function cannot(iterable|string $abilities, mixed $arguments = []): bool
    {
        return $this->cant($abilities, $arguments);
    }

    /**
     * Resolve the gate manager from the container.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    protected function gateManager(): GateManagerInterface
    {
        return ApplicationContext::getContainer()->get(GateManagerInterface::class);
    }
}
