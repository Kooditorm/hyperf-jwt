<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Claims\Claim;
use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Claims\Factory as ClaimFactory;
use Kooditorm\Hyperf\Jwt\Support\CustomClaims;
use Kooditorm\Hyperf\Jwt\Support\RefreshFlow;
use Kooditorm\Hyperf\Jwt\Validators\PayloadValidator;

class Factory
{
    use CustomClaims;
    use RefreshFlow;

    protected ClaimFactory $claimFactory;

    protected PayloadValidator $validator;

    protected array $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    protected Collection $claims;

    public function __construct(ClaimFactory $claimFactory, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->validator = $validator;
        $this->claims = new Collection();
    }

    public function make(bool $resetClaims = false): Payload
    {
        if ($resetClaims) {
            $this->emptyClaims();
        }

        return $this->withClaims($this->buildClaimsCollection());
    }

    public function emptyClaims(): static
    {
        $this->claims = new Collection();

        return $this;
    }

    protected function addClaims(array $claims): static
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    protected function addClaim(string $name, mixed $value): static
    {
        $this->claims->put($name, $value);

        return $this;
    }

    protected function buildClaims(): static
    {
        // Remove the exp claim if the ttl is null
        if ($this->claimFactory->getTTL() === null) {
            if (($key = array_search('exp', $this->defaultClaims)) !== false) {
                unset($this->defaultClaims[$key]);
            }
        }

        // Add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // Add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    protected function resolveClaims(): Collection
    {
        return $this->claims->map(function ($value, $name) {
            return $value instanceof Claim ? $value : $this->claimFactory->get($name, $value);
        });
    }

    public function buildClaimsCollection(): Collection
    {
        return $this->buildClaims()->resolveClaims();
    }

    public function withClaims(Collection $claims): Payload
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    public function setDefaultClaims(array $claims): static
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    public function setTTL(?int $ttl): static
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    public function getTTL(): ?int
    {
        return $this->claimFactory->getTTL();
    }

    public function getDefaultClaims(): array
    {
        return $this->defaultClaims;
    }

    public function validator(): PayloadValidator
    {
        return $this->validator;
    }

    public function __call(string $method, array $parameters): static
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
