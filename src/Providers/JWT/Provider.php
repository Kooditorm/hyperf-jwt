<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Providers\JWT;

use Hyperf\Collection\Arr;

abstract class Provider
{
    public const ALGO_HS256 = 'HS256';
    public const ALGO_HS384 = 'HS384';
    public const ALGO_HS512 = 'HS512';
    public const ALGO_RS256 = 'RS256';
    public const ALGO_RS384 = 'RS384';
    public const ALGO_RS512 = 'RS512';
    public const ALGO_ES256 = 'ES256';
    public const ALGO_ES384 = 'ES384';
    public const ALGO_ES512 = 'ES512';

    protected ?string $secret;

    protected array $keys;

    protected string $algo;

    public function __construct(?string $secret, string $algo, array $keys)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
    }

    public function setAlgo(string $algo): static
    {
        $this->algo = $algo;

        return $this;
    }

    public function getAlgo(): string
    {
        return $this->algo;
    }

    public function setSecret(?string $secret): static
    {
        $this->secret = $secret;

        return $this;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function setKeys(array $keys): static
    {
        $this->keys = $keys;

        return $this;
    }

    public function getKeys(): array
    {
        return $this->keys;
    }

    public function getPublicKey(): ?string
    {
        return Arr::get($this->keys, 'public');
    }

    public function getPrivateKey(): ?string
    {
        return Arr::get($this->keys, 'private');
    }

    public function getPassphrase(): ?string
    {
        return Arr::get($this->keys, 'passphrase');
    }

    protected function getSigningKey(): ?string
    {
        return $this->isAsymmetric() ? $this->getPrivateKey() : $this->getSecret();
    }

    protected function getVerificationKey(): ?string
    {
        return $this->isAsymmetric() ? $this->getPublicKey() : $this->getSecret();
    }

    abstract protected function isAsymmetric(): bool;
}
