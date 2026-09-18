<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt;

use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Claims\Factory as ClaimFactory;
use Kooditorm\Hyperf\Jwt\Contracts\ClaimInterface;

class PayloadFactory
{
    /**
     * The default claims.
     *
     * @var list<string>
     */
    protected array $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    public function __construct(protected readonly ClaimFactory $claimFactory)
    {
    }

    /**
     * Create the Payload instance.
     */
    public function make(array $claims, bool $ignoreExpired = false): Payload
    {
        return new Payload($this->resolveClaims($this->buildClaims($claims)), $ignoreExpired);
    }

    /**
     * Set the default claims to be added to the Payload.
     */
    public function setDefaultClaims(array $claims): static
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Get the default claims.
     *
     * @return list<string>
     */
    public function getDefaultClaims(): array
    {
        return $this->defaultClaims;
    }

    /**
     * Helper to set the ttl.
     */
    public function setTtl(int $ttl): static
    {
        $this->claimFactory->setTtl($ttl);

        return $this;
    }

    /**
     * Helper to get the ttl.
     */
    public function getTtl(): int
    {
        return (int) $this->claimFactory->getTtl();
    }

    /**
     * Build the default claims.
     */
    protected function buildClaims(array $claims): Collection
    {
        $collection = new Collection();
        $defaultClaims = $this->getDefaultClaims();

        // remove the exp claim if it exists and the ttl is null
        if ($this->claimFactory->getTtl() === null && $key = array_search('exp', $defaultClaims, true)) {
            unset($defaultClaims[$key]);
        }

        // add the default claims
        foreach ($defaultClaims as $claim) {
            $collection->put($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        foreach ($claims as $name => $value) {
            $collection->put($name, $value);
        }

        return $collection;
    }

    /**
     * Build out the Claim DTO's.
     */
    protected function resolveClaims(Collection $claims): Collection
    {
        return $claims->map(function ($value, $name) {
            return $value instanceof ClaimInterface ? $value : $this->claimFactory->get($name, $value);
        });
    }
}
