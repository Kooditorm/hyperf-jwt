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
use Kooditorm\Hyperf\Auth\Access\Response;
use Throwable;

class AuthorizationException extends Exception
{
    /**
     * The response from the gate.
     */
    protected ?Response $response = null;

    /**
     * Create a new authorization exception instance.
     */
    public function __construct(?string $message = null, mixed $code = null, ?Throwable $previous = null)
    {
        parent::__construct($message ?? 'This action is unauthorized.', 0, $previous);

        $this->code = $code ?: 0;
    }

    /**
     * Get the response from the gate.
     */
    public function getResponse(): ?Response
    {
        return $this->response;
    }

    /**
     * Set the response from the gate.
     */
    public function setResponse(Response $response): self
    {
        $this->response = $response;

        return $this;
    }

    /**
     * Create a deny response object from this exception.
     */
    public function toResponse(): Response
    {
        return Response::deny($this->message, (int) $this->code);
    }
}
