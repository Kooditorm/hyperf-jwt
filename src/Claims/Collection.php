<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Hyperf\Collection\Collection as HyperfCollection;
use Hyperf\Stringable\Str;

class Collection extends HyperfCollection
{
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by its unique name.
     */
    public function getByClaimName(string $name, ?callable $callback = null, mixed $default = null): ?Claim
    {
        return $this->filter(function (Claim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim under a given context.
     */
    public function validate(string $context = 'payload'): static
    {
        $args = func_get_args();
        array_shift($args);

        $this->each(function ($claim) use ($context, $args) {
            call_user_func_array(
                [$claim, 'validate' . Str::ucfirst($context)],
                $args
            );
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     */
    public function hasAllClaims(mixed $claims): bool
    {
        return count($claims) && (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as a plain key/value array.
     */
    public function toPlainArray(): array
    {
        return $this->map(function (Claim $claim) {
            return $claim->getValue();
        })->toArray();
    }

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
            if (! is_string($key) && $value instanceof Claim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
