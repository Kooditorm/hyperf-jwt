<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Hyperf\HttpServer\Contract\RequestInterface;
use Psr\Container\ContainerInterface;
use Kooditorm\Hyperf\Jwt\Support\Utils;

class Factory
{
    /**
     * The container for resolving the request per-coroutine.
     */
    protected ContainerInterface $container;

    /**
     * The configured issuer string, or null to auto-detect from request.
     */
    protected ?string $issuer = null;

    /**
     * The TTL in minutes.
     */
    protected ?int $ttl = 60;

    /**
     * Time leeway in seconds.
     */
    protected int $leeway = 0;

    /**
     * The classes map for built-in claims.
     */
    private array $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * Get the instance of the claim when passing the name and value.
     */
    public function get(string $name, mixed $value): Claim
    {
        if ($this->has($name)) {
            $claim = new $this->classMap[$name]($value);

            return method_exists($claim, 'setLeeway')
                ? $claim->setLeeway($this->leeway)
                : $claim;
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim name is a built-in claim.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * Generate the initial value and return the Claim instance.
     */
    public function make(string $name): Claim
    {
        return $this->get($name, $this->{$name}());
    }

    /**
     * Get the Issuer (iss) claim.
     * Uses configured issuer, or falls back to the request URL.
     */
    public function iss(): string
    {
        if ($this->issuer !== null) {
            return $this->issuer;
        }

        try {
            $request = $this->container->get(RequestInterface::class);
            if ($request instanceof RequestInterface) {
                $uri = $request->getUri();
                $scheme = $uri->getScheme();
                $host = $uri->getHost();
                $port = $uri->getPort();
                $base = $scheme . '://' . $host;
                if ($port && ! in_array($port, [80, 443])) {
                    $base .= ':' . $port;
                }
                return $base;
            }
        } catch (\Throwable) {
            // If we can't get the request (e.g. CLI context), return a default
        }

        return 'hyperf-jwt';
    }

    /**
     * Get the Issued At (iat) claim.
     */
    public function iat(): int
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the Expiration (exp) claim.
     */
    public function exp(): int
    {
        return Utils::now()->addMinutes((int) $this->ttl)->getTimestamp();
    }

    /**
     * Get the Not Before (nbf) claim.
     */
    public function nbf(): int
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the JWT Id (jti) claim.
     */
    public function jti(): string
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * Add a new claim mapping.
     */
    public function extend(string $name, string $classPath): static
    {
        $this->classMap[$name] = $classPath;

        return $this;
    }

    public function setIssuer(?string $issuer): static
    {
        $this->issuer = $issuer;

        return $this;
    }

    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    public function setTTL(?int $ttl): static
    {
        $this->ttl = $ttl;

        return $this;
    }

    public function getTTL(): ?int
    {
        return $this->ttl;
    }

    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }
}
