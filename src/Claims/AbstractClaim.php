<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Claims;

use Kooditorm\Hyperf\Jwt\Contracts\ClaimInterface;
use JsonSerializable;

/**
 * Base claim implementation. Claims are immutable: setValue()/withLeeway()
 * return cloned instances.
 */
abstract class AbstractClaim implements ClaimInterface, JsonSerializable
{
    protected string $name;

    protected mixed $value;

    /**
     * Clock-skew tolerance in seconds, applied by time-based claims.
     */
    protected int $leeway = 0;

    public function __construct(mixed $value = null)
    {
        $this->value = $value;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getValue(): mixed
    {
        return $this->value;
    }

    public function setValue(mixed $value): static
    {
        $clone = clone $this;
        $clone->value = $value;

        return $clone;
    }

    /**
     * Return a cloned instance with the given leeway.
     */
    public function withLeeway(int $leeway): static
    {
        $clone = clone $this;
        $clone->leeway = $leeway;

        return $clone;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * Default validation: strict equality between the claim value and the
     * value read from the token. Time-based claims override this.
     */
    public function validate(mixed $value): bool
    {
        return $value === $this->getValue();
    }

    /**
     * JSON representation is just the raw value.
     */
    public function jsonSerialize(): mixed
    {
        return $this->value;
    }
}
