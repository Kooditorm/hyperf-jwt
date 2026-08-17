<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts\Auth;

interface Factory
{
    /**
     * Get a guard instance by name.
     *
     * @param  string|null  $name
     */
    public function guard($name = null);
}