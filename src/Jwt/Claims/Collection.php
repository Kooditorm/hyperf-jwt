<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Claims;

use Hyperf\Collection\Collection as HyperfCollection;

/**
 * @template TKey of array-key
 * @template TValue
 *
 * @extends HyperfCollection<TKey, TValue>
 */
class Collection extends HyperfCollection
{
    /**
     * Create a new collection.
     */
    public function __construct(mixed $items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     */
    public function getByClaimName(string $name, ?callable $callback = null, mixed $default = null): AbstractClaim
    {
        return $this->filter(function (AbstractClaim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim.
     */
    public function validate(bool $ignoreExpired = false): static
    {
        $this->each(function ($claim) use ($ignoreExpired) {
            $claim->validate($ignoreExpired);
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     */
    public function hasAllClaims(mixed $claims): bool
    {
        return count($claims) > 0 && (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     */
    public function toPlainArray(): array
    {
        return $this->map(function (AbstractClaim $claim) {
            return $claim->getValue();
        })->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items): array
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     */
    private function sanitizeClaims(mixed $items): array
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (! is_string($key) and $value instanceof AbstractClaim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
