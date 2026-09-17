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

use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\AnnotationCollector;
use Kooditorm\Hyperf\Auth\Annotations\Policy;
use Kooditorm\Hyperf\Auth\Contracts\Access\GateInterface;
use Kooditorm\Hyperf\Auth\Contracts\Access\GateManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;
use Kooditorm\Hyperf\Auth\Events\GateManagerResolved;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function Hyperf\Support\call;
use function Hyperf\Support\make;

class GateManager implements GateManagerInterface
{
    /**
     * The container instance.
     */
    protected ContainerInterface $container;

    /**
     * The config instance.
     */
    protected ConfigInterface $config;

    /**
     * The access gate instance.
     */
    protected GateInterface $gate;

    /**
     * The event dispatcher instance.
     */
    protected EventDispatcherInterface $eventDispatcher;

    /**
     * The auth manager instance.
     */
    protected AuthManagerInterface $auth;

    /**
     * Create a new Gate manager instance.
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $container->get(ConfigInterface::class);
        $this->eventDispatcher = $container->get(EventDispatcherInterface::class);
        $this->auth = $container->get(AuthManagerInterface::class);

        $this->gate = make(Gate::class, [
            'userResolver' => function () {
                return call($this->auth->userResolver());
            },
        ]);

        $this->registerPoliciesByConfig();
        $this->registerPoliciesByAnnotation();

        $this->eventDispatcher->dispatch(new GateManagerResolved($this));
    }

    /**
     * Dynamically call the default driver instance.
     */
    public function __call(string $method, array $parameters): mixed
    {
        return $this->gate->{$method}(...$parameters);
    }

    /**
     * Get the underlying gate instance.
     */
    public function getGate(): GateInterface
    {
        return $this->gate;
    }

    /**
     * Register the application's policies by config.
     */
    protected function registerPoliciesByConfig(): void
    {
        $policies = (array) $this->config->get('auth.policies', []);

        foreach ($policies as $model => $policy) {
            $this->gate->policy((string) $model, (string) $policy);
        }
    }

    /**
     * Register the application's policies by annotation.
     */
    protected function registerPoliciesByAnnotation(): void
    {
        $policies = (array) AnnotationCollector::getClassesByAnnotation(Policy::class);

        foreach ($policies as $policy => $annotation) {
            foreach ((array) ($annotation->models ?? []) as $model) {
                $this->gate->policy((string) $model, (string) $policy);
            }
        }
    }
}
