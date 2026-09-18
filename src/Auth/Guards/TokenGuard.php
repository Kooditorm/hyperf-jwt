<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Auth\Guards;

use Hyperf\Stringable\Str;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Auth\Contracts\GuardInterface;
use Kooditorm\Hyperf\Auth\Contracts\UserProviderInterface;
use Kooditorm\Hyperf\Auth\GuardHelpers;
use Psr\Http\Message\ServerRequestInterface;

class TokenGuard implements GuardInterface
{
    use GuardHelpers;

    /**
     * The name of the query string item from the request containing the API token.
     */
    protected string $inputKey;

    /**
     * The name of the token "column" in persistent storage.
     */
    protected string $storageKey;

    /**
     * Indicates if the API token is hashed in storage.
     */
    protected bool $hash = false;

    /**
     * Create a new authentication guard.
     */
    public function __construct(
        protected ServerRequestInterface $request,
        UserProviderInterface $provider,
        string $name,
        array $options = []
    ) {
        $this->provider = $provider;
        $this->inputKey = $options['input_key'] ?? 'api_token';
        $this->storageKey = $options['storage_key'] ?? 'api_token';
        $this->hash = $options['hash'] ?? false;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticatableInterface
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (! empty($token)) {
            $user = $this->provider->retrieveByCredentials([
                $this->storageKey => $this->hash ? hash('sha256', $token) : $token,
            ]);
        }

        return $this->user = $user;
    }

    /**
     * Get the token for the current request.
     */
    public function getTokenForRequest(): string
    {
        $token = $this->request->query($this->inputKey);

        if (empty($token)) {
            $token = $this->request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $this->getBearerToken();
        }

        if (empty($token)) {
            $token = $this->getBasicAuthorization()[1] ?? '';
        }

        return $token;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        if (empty($credentials[$this->inputKey])) {
            return false;
        }

        $credentials = [$this->storageKey => $credentials[$this->inputKey]];

        return $this->provider->retrieveByCredentials($credentials) !== null;
    }

    /**
     * Set the current request instance.
     */
    public function setRequest(ServerRequestInterface $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the bearer token from the request headers.
     */
    protected function getBearerToken(): ?string
    {
        $header = $this->request->header('Authorization', '');

        if (Str::startsWith($header, 'Bearer ')) {
            return Str::substr($header, 7);
        }

        return null;
    }

    /**
     * Get the basic authorization credentials from the request headers.
     *
     * @return array{0: ?string, 1: ?string}
     */
    protected function getBasicAuthorization(): array
    {
        $header = (string) $this->request->header('Authorization');

        if (Str::startsWith($header, 'Basic ')) {
            return explode(':', base64_decode(Str::substr($header, 6)));
        }

        return [null, null];
    }
}
