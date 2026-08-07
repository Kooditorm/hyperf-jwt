<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Payload;

use ArrayAccess;
use Countable;
use Kooditorm\Hyperf\Jwt\Claims\AbstractClaim;
use Kooditorm\Hyperf\Jwt\Contracts\ClaimInterface;
use OutOfBoundsException;

/**
 * An immutable collection of JWT claims.
 */
class Payload implements ArrayAccess, Countable
{
    /**
     * @param array<string,ClaimInterface> $claims
     */
    public function __construct(protected array $claims = [])
    {
    }

    /**
     * Flat name => value array (for JSON serialization).
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $data = [];
        foreach ($this->claims as $name => $claim) {
            $data[$name] = $claim->getValue();
        }

        return $data;
    }

    public function get(string $name): ?ClaimInterface
    {
        return $this->claims[$name] ?? null;
    }

    public function has(string $name): bool
    {
        return isset($this->claims[$name]);
    }

    /**
     * The raw value of a claim, throwing if it is absent.
     */
    public function value(string $name): mixed
    {
        if (! $this->has($name)) {
            throw new OutOfBoundsException(sprintf('Claim [%s] not found in payload.', $name));
        }

        return $this->claims[$name]->getValue();
    }

    public function count(): int
    {
        return count($this->claims);
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->has($offset);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->get($offset)?->getValue();
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new \LogicException('Payload is immutable; cannot set claim.');
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new \LogicException('Payload is immutable; cannot unset claim.');
    }

    public function __toString(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
    }
}
