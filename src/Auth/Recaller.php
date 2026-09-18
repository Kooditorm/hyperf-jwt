<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth;

use Hyperf\Stringable\Str;

class Recaller
{
    /**
     * The "recaller" / "remember me" cookie string.
     */
    protected string $recaller;

    /**
     * Create a new recaller instance.
     */
    public function __construct(string $recaller)
    {
        $this->recaller = @unserialize($recaller, ['allowed_classes' => false]) ?: $recaller;
    }

    /**
     * Get the user ID from the recaller.
     */
    public function id(): string
    {
        return explode('|', $this->recaller, 3)[0];
    }

    /**
     * Get the "remember token" token from the recaller.
     */
    public function token(): string
    {
        return explode('|', $this->recaller, 3)[1];
    }

    /**
     * Get the password from the recaller.
     */
    public function hash(): string
    {
        return explode('|', $this->recaller, 3)[2];
    }

    /**
     * Determine if the recaller is valid.
     */
    public function valid(): bool
    {
        return $this->properString() && $this->hasAllSegments();
    }

    /**
     * Determine if the recaller is an invalid string.
     */
    protected function properString(): bool
    {
        return Str::contains($this->recaller, '|');
    }

    /**
     * Determine if the recaller has all segments.
     */
    protected function hasAllSegments(): bool
    {
        $segments = explode('|', $this->recaller);

        return count($segments) === 3 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
}
