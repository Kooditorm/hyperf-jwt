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

use Hyperf\Contract\Arrayable;
use Kooditorm\Hyperf\Auth\Exceptions\AuthorizationException;

class Response implements Arrayable
{
    /**
     * Indicates whether the response was allowed.
     */
    protected bool $allowed;

    /**
     * The response message.
     */
    protected ?string $message;

    /**
     * The response code.
     */
    protected mixed $code;

    /**
     * Create a new response.
     *
     * @param mixed $code
     */
    public function __construct(bool $allowed, ?string $message = null, mixed $code = null)
    {
        $this->code = $code;
        $this->allowed = $allowed;
        $this->message = $message;
    }

    /**
     * Get the string representation of the message.
     */
    public function __toString(): string
    {
        return (string) $this->message();
    }

    /**
     * Create a new "allow" Response.
     *
     * @param mixed $code
     */
    public static function allow(?string $message = null, mixed $code = null): static
    {
        return new static(true, $message, $code);
    }

    /**
     * Create a new "deny" Response.
     *
     * @param mixed $code
     */
    public static function deny(?string $message = null, mixed $code = null): static
    {
        return new static(false, $message, $code);
    }

    /**
     * Determine if the response was allowed.
     */
    public function allowed(): bool
    {
        return $this->allowed;
    }

    /**
     * Determine if the response was denied.
     */
    public function denied(): bool
    {
        return ! $this->allowed();
    }

    /**
     * Get the response message.
     */
    public function message(): ?string
    {
        return $this->message;
    }

    /**
     * Get the response code / reason.
     */
    public function code(): mixed
    {
        return $this->code;
    }

    /**
     * Throw authorization exception if response was denied.
     *
     * @throws AuthorizationException
     */
    public function authorize(): static
    {
        if ($this->denied()) {
            throw (new AuthorizationException($this->message(), $this->code()))
                ->setResponse($this);
        }

        return $this;
    }

    /**
     * Convert the response to an array.
     */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed(),
            'message' => $this->message(),
            'code' => $this->code(),
        ];
    }
}
