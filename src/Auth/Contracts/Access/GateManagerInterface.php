<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Contracts\Access;

use Kooditorm\Hyperf\Auth\Access\Response;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;

/**
 * The manager forwards every gate call to the underlying gate instance, so the
 * full gate API is mirrored here for static analysis and IDE completion.
 *
 * @method bool has(string|array $ability)
 * @method GateInterface define(string $ability, callable|string $callback)
 * @method GateInterface resource(string $name, string $class, ?array $abilities = null)
 * @method GateInterface policy(string $class, string $policy)
 * @method GateInterface before(callable $callback)
 * @method GateInterface after(callable $callback)
 * @method bool allows(string $ability, mixed $arguments = [])
 * @method bool denies(string $ability, mixed $arguments = [])
 * @method bool check(iterable|string $abilities, mixed $arguments = [])
 * @method bool any(iterable|string $abilities, mixed $arguments = [])
 * @method bool none(iterable|string $abilities, mixed $arguments = [])
 * @method Response authorize(string $ability, mixed $arguments = [])
 * @method Response inspect(string $ability, mixed $arguments = [])
 * @method mixed raw(string $ability, mixed $arguments = [])
 * @method mixed getPolicyFor(object|string $class)
 * @method mixed resolvePolicy(object|string $class)
 * @method GateInterface forUser(AuthenticatableInterface $user)
 * @method GateInterface guessPolicyNamesUsing(callable $callback)
 * @method array abilities()
 * @method array policies()
 */
interface GateManagerInterface
{
    /**
     * Get the underlying gate instance.
     */
    public function getGate(): GateInterface;
}
