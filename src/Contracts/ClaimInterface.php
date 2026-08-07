<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Contracts;

/**
 * A single JWT claim (e.g. `iss`, `exp`, `sub` or any custom claim).
 */
interface ClaimInterface
{
    /**
     * The claim name.
     */
    public function getName(): string;

    /**
     * The claim value.
     */
    public function getValue(): mixed;

    /**
     * Set a new value and return a (cloned) instance.
     */
    public function setValue(mixed $value): static;

    /**
     * Validate the claim against a given value (used during verification).
     */
    public function validate(mixed $value): bool;
}
