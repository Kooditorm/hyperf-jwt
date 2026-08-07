<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Providers\JWT;

use Composer\InstalledVersions;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\JWT as JWTContract;
use Kooditorm\Hyperf\Jwt\Exceptions\JWTException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;
use function Hyperf\Collection\collect;

class Lcobucci extends Provider implements JWTContract
{
    protected Signer $signer;

    protected Configuration $config;

    /**
     * Supported signers mapped by algorithm.
     */
    protected array $signers = [
        self::ALGO_HS256 => Signer\Hmac\Sha256::class,
        self::ALGO_HS384 => Signer\Hmac\Sha384::class,
        self::ALGO_HS512 => Signer\Hmac\Sha512::class,
        self::ALGO_RS256 => Signer\Rsa\Sha256::class,
        self::ALGO_RS384 => Signer\Rsa\Sha384::class,
        self::ALGO_RS512 => Signer\Rsa\Sha512::class,
        self::ALGO_ES256 => Signer\Ecdsa\Sha256::class,
        self::ALGO_ES384 => Signer\Ecdsa\Sha384::class,
        self::ALGO_ES512 => Signer\Ecdsa\Sha512::class,
    ];

    public function __construct(?string $secret, string $algo, array $keys, ?Configuration $config = null)
    {
        parent::__construct($secret, $algo, $keys);

        $this->signer = $this->getSigner();
        $this->config = $config ?: $this->buildConfig();
    }

    public function encode(array $payload): string
    {
        $builder = $this->getBuilderFromClaims($payload);

        try {
            return $builder
                ->getToken($this->config->signer(), $this->config->signingKey())
                ->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    public function decode(string $token): array
    {
        try {
            /** @var \Lcobucci\JWT\Token\Plain $parsed */
            $parsed = $this->config->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }

        $constraints = $this->config->validationConstraints();

        if (! $this->config->validator()->validate($parsed, ...$constraints)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return collect($parsed->claims()->all())
            ->map(function ($claim) {
                if ($claim instanceof DateTimeInterface) {
                    return $claim->getTimestamp();
                }

                return is_object($claim) && method_exists($claim, 'getValue')
                    ? $claim->getValue()
                    : $claim;
            })
            ->toArray();
    }

    protected function getBuilderFromClaims(array $payload): Builder
    {
        $builder = $this->config->builder();

        foreach ($payload as $key => $value) {
            $builder = match ($key) {
                RegisteredClaims::ID => $builder->identifiedBy((string) $value),
                RegisteredClaims::EXPIRATION_TIME => $builder->expiresAt(
                    DateTimeImmutable::createFromFormat('U', (string) $value) ?: null
                ),
                RegisteredClaims::NOT_BEFORE => $builder->canOnlyBeUsedAfter(
                    DateTimeImmutable::createFromFormat('U', (string) $value) ?: null
                ),
                RegisteredClaims::ISSUED_AT => $builder->issuedAt(
                    DateTimeImmutable::createFromFormat('U', (string) $value) ?: null
                ),
                RegisteredClaims::ISSUER => $builder->issuedBy((string) $value),
                RegisteredClaims::AUDIENCE => $builder->permittedFor((string) $value),
                RegisteredClaims::SUBJECT => $builder->relatedTo((string) $value),
                default => $builder->withClaim($key, $value),
            };
        }

        return $builder;
    }

    protected function buildConfig(): Configuration
    {
        $config = $this->isAsymmetric()
            ? Configuration::forAsymmetricSigner(
                $this->signer,
                $this->getSigningKeyObject(),
                $this->getVerificationKeyObject()
            )
            : Configuration::forSymmetricSigner($this->signer, $this->getSigningKeyObject());

        $constraint = new SignedWith($this->signer, $this->getVerificationKeyObject());

        // Support both lcobucci/jwt 4.x and 5.x API
        if (method_exists($config, 'withValidationConstraints')) {
            return $config->withValidationConstraints($constraint);
        }

        // Fallback for 4.x (setValidationConstraints was removed in 5.x)
        if (method_exists($config, 'setValidationConstraints')) {
            $config->setValidationConstraints($constraint);
        }

        return $config;
    }

    protected function getSigner(): Signer
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        $signerClass = $this->signers[$this->algo];

        // ECDSA signers require the create() factory method in both v4 and v5
        if (is_subclass_of($signerClass, Ecdsa::class)) {
            return $signerClass::create();
        }

        return new $signerClass();
    }

    protected function isAsymmetric(): bool
    {
        return is_subclass_of($this->signer, Rsa::class)
            || is_subclass_of($this->signer, Ecdsa::class);
    }

    protected function getSigningKeyObject(): Key
    {
        if ($this->isAsymmetric()) {
            if (! $privateKey = $this->getPrivateKey()) {
                throw new JWTException('Private key is not set.');
            }

            return InMemory::plainText($privateKey, $this->getPassphrase() ?? '');
        }

        if (! $secret = $this->getSecret()) {
            throw new JWTException('Secret is not set.');
        }

        return InMemory::plainText($secret);
    }

    protected function getVerificationKeyObject(): Key
    {
        if ($this->isAsymmetric()) {
            if (! $public = $this->getPublicKey()) {
                throw new JWTException('Public key is not set.');
            }

            return InMemory::plainText($public);
        }

        if (! $secret = $this->getSecret()) {
            throw new JWTException('Secret is not set.');
        }

        return InMemory::plainText($secret);
    }
}
