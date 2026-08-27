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
     *
     * @var \Psr\Container\ContainerInterface
     */
    protected $container;

    /**
     * The config instance.
     *
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $config;

    /**
     * The assess gate instance.
     *
     * @var \Hyperf\Contract\ConfigInterface
     */
    protected $gate;

    /**
     * The event dispatcher instance.
     *
     * @var \Psr\EventDispatcher\EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * The event dispatcher instance.
     *
     * @var \Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface
     */
    protected $auth;

    /**
     * Create a new Auth manager instance.
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $container->get(ConfigInterface::class);
        $this->eventDispatcher = $container->get(EventDispatcherInterface::class);
        $this->auth = $container->get(AuthManagerInterface::class);
        $this->gate = make(Gate::class, ['userResolver' => function () {
            return call($this->auth->userResolver());
        }]);
        $this->registerPoliciesByConfig();
        $this->registerPoliciesByAnnotation();
        $this->eventDispatcher->dispatch(new GateManagerResolved($this));
    }

    /**
     * Dynamically call the default driver instance.
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        return $this->gate->{$method}(...$parameters);
    }

    /**
     * Register the application's policies by config.
     */
    protected function registerPoliciesByConfig(): void
    {
        $policies = $this->config->get('auth.policies', []);
        foreach ($policies as $model => $policy) {
            $this->gate->policy($model, $policy);
        }
    }

    /**
     * Register the application's policies by annotation.
     */
    protected function registerPoliciesByAnnotation(): void
    {
        $policies = AnnotationCollector::getClassesByAnnotation(Policy::class);
        foreach ($policies as $policy => $annotation) {
            foreach ($annotation->models as $model) {
                $this->gate->policy($model, $policy);
            }
        }
    }
}