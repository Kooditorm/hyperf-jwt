<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Exceptions;

use Exception;

class AuthenticationException extends Exception
{
    /**
     * All of the guards that were checked.
     *
     * @var array
     */
    protected array $guards;

    /**
     * The path the user should be redirected to.
     *
     * @var string|null
     */
    protected string|null $redirectTo;

    /**
     * Create a new authentication exception.
     *
     * @param string $message
     * @param array $guards
     * @param string|null $redirectTo
     */
    public function __construct(string $message = 'Unauthenticated.', array $guards = [], string|null $redirectTo = null)
    {
        parent::__construct($message, 401);
        $this->guards = $guards;
        $this->redirectTo = $redirectTo;
    }

    /**
     * Get the guards that were checked.
     *
     * @return array
     */
    public function guards(): array
    {
        return $this->guards;
    }

    /**
     * Get the path the user should be redirected to.
     *
     * @return string|null
     */
    public function redirectTo(): string|null
    {
        return $this->redirectTo;
    }
}