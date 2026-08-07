<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use ArrayAccess;
use BadMethodCallException;
use Countable;
use Hyperf\Collection\Arr;
use Hyperf\Contract\Arrayable;
use Hyperf\Stringable\Str;
use JsonSerializable;
use Kooditorm\Hyperf\Jwt\Claims\Claim;
use Kooditorm\Hyperf\Jwt\Claims\Collection;
use Kooditorm\Hyperf\Jwt\Exceptions\PayloadException;
use Kooditorm\Hyperf\Jwt\Validators\PayloadValidator;

class Payload implements ArrayAccess, Arrayable, Countable, JsonSerializable
{
    private Collection $claims;

    public function __construct(Collection $claims, PayloadValidator $validator, bool $refreshFlow = false)
    {
        $this->claims = $validator->setRefreshFlow($refreshFlow)->check($claims);
    }

    public function getClaims(): Collection
    {
        return $this->claims;
    }

    /**
     * Checks if a payload matches some expected values.
     */
    public function matches(array $values, bool $strict = false): bool
    {
        if (empty($values)) {
            return false;
        }

        $claims = $this->getClaims();

        foreach ($values as $key => $value) {
            if (! $claims->has($key) || ! $claims->get($key)->matches($value, $strict)) {
                return false;
            }
        }

        return true;
    }

    public function matchesStrict(array $values): bool
    {
        return $this->matches($values, true);
    }

    /**
     * Get the payload value(s).
     */
    public function get(string|array|null $claim = null): mixed
    {
        if ($claim !== null) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return Arr::get($this->toArray(), $claim);
        }

        return $this->toArray();
    }

    /**
     * Get the underlying Claim instance.
     */
    public function getInternal(string $claim): ?Claim
    {
        return $this->claims->getByClaimName($claim);
    }

    public function has(Claim $claim): bool
    {
        return $this->claims->has($claim->getName());
    }

    public function hasKey(string $claim): bool
    {
        return $this->offsetExists($claim);
    }

    public function toArray(): array
    {
        return $this->claims->toPlainArray();
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    public function __toString(): string
    {
        return $this->toJson();
    }

    public function offsetExists(mixed $key): bool
    {
        return Arr::has($this->toArray(), $key);
    }

    public function offsetGet(mixed $key): mixed
    {
        return Arr::get($this->toArray(), $key);
    }

    public function offsetSet(mixed $key, mixed $value): void
    {
        throw new PayloadException('The payload is immutable');
    }

    public function offsetUnset(mixed $key): void
    {
        throw new PayloadException('The payload is immutable');
    }

    public function count(): int
    {
        return count($this->toArray());
    }

    public function __invoke(string|null $claim = null): mixed
    {
        return $this->get($claim);
    }

    public function __call(string $method, array $parameters): mixed
    {
        if (preg_match('/get(.+)\b/i', $method, $matches)) {
            foreach ($this->claims as $claim) {
                if (get_class($claim) === 'Kooditorm\\Hyperf\\Jwt\\Claims\\' . $matches[1]) {
                    return $claim->getValue();
                }
            }
        }

        throw new BadMethodCallException(
            sprintf('The claim [%s] does not exist on the payload.', Str::after($method, 'get'))
        );
    }
}
