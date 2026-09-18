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

use Hyperf\Context\ApplicationContext;
use Hyperf\Contract\Arrayable;
use Hyperf\Contract\Jsonable;
use JsonSerializable;
use Kooditorm\Hyperf\Jwt\Contracts\ClaimInterface;
use Kooditorm\Hyperf\Jwt\Contracts\ManagerInterface;

class AbstractClaim implements ClaimInterface, Arrayable, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     */
    protected string $name = '';

    /**
     * The claim value.
     */
    private mixed $value = null;

    private ?Factory $factory = null;

    public function __construct(mixed $value)
    {
        $this->setValue($value);
    }

    /**
     * Get the payload as a string.
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Set the claim value, and call a validate method.
     *
     * @return $this
     */
    public function setValue(mixed $value)
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate the claim in a standalone Claim context.
     */
    public function validateCreate(mixed $value)
    {
        return $value;
    }

    /**
     * Validate the Claim value.
     */
    public function validate(bool $ignoreExpired = false): bool
    {
        return true;
    }

    /**
     * Checks if the value matches the claim.
     */
    public function matches(mixed $value, bool $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    protected function getFactory(): Factory
    {
        if ($this->factory !== null) {
            return $this->factory;
        }

        return $this->factory = ApplicationContext::getContainer()
            ->get(ManagerInterface::class)
            ->getClaimFactory();
    }
}
