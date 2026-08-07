<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts\Providers;

interface Auth
{
    /**
     * Check a user's credentials.
     */
    public function byCredentials(array $credentials): bool;

    /**
     * Authenticate a user via the id.
     */
    public function byId(mixed $id): bool;

    /**
     * Get the currently authenticated user.
     */
    public function user(): mixed;
}
