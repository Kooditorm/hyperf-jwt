<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Aspect;

use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Kooditorm\Hyperf\Auth\Annotations\Auth;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Exceptions\AuthenticationException;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;


/**
 * @Aspect
 */
class AuthAspect extends  AbstractAspect
{
    public array $annotations = [
        Auth::class,
    ];

    /**
     * @Inject
     * @var AuthManagerInterface
     */
    protected $auth;

    public function process(ProceedingJoinPoint $proceedingJoinPoint)
    {
        $annotation = $proceedingJoinPoint->getAnnotationMetadata();

        $authAnnotation = $annotation->class[Auth::class] ?? $annotation->method[Auth::class];

        $guards = empty($authAnnotation->guards) ? [null] : $authAnnotation->guards;
        $passable = $authAnnotation->passable;

        foreach ($guards as $name) {
            $guard = $this->auth->guard($name);

            if (! $guard->user() instanceof AuthenticatableInterface and ! $passable) {
                throw new AuthenticationException('Unauthenticated.', $guards);
            }
        }

        return $proceedingJoinPoint->process();
    }
}