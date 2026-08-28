<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Events;

use Psr\Http\Message\ServerRequestInterface;

class Lockout
{
    /**
     * The throttled request.
     *
     * @var ServerRequestInterface
     */
    public $request;

    /**
     * Create a new event instance.
     */
    public function __construct(ServerRequestInterface $request)
    {
        $this->request = $request;
    }
}