<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Http\Parser;

use Psr\Http\Message\ServerRequestInterface;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;

class Cookies implements ParserContract
{
    use KeyTrait;

    private bool $decrypt;

    public function __construct(bool $decrypt = false)
    {
        $this->decrypt = $decrypt;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();

        if (! isset($cookies[$this->key])) {
            return null;
        }

        $value = $cookies[$this->key];

        // If decryption is needed, the user should provide their own
        // decryption logic by extending this class or using a custom parser.
        // Hyperf does not have a built-in cookie encryption like Laravel.
        if ($this->decrypt) {
            return $this->decrypt($value);
        }

        return $value;
    }

    /**
     * Override this method to provide custom decryption logic.
     */
    protected function decrypt(string $value): ?string
    {
        return $value;
    }
}
