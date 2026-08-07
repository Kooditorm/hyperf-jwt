<?php

declare(strict_types=1);

namespace HyperfExt\Jwt;

use Hyperf\Cache\CacheFactory;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\ContainerInterface;
use HyperfExt\Jwt\Blacklist\Blacklist;
use HyperfExt\Jwt\Blacklist\BlacklistStorage;
use HyperfExt\Jwt\Claims\Factory as ClaimFactory;
use HyperfExt\Jwt\Payload\PayloadValidator;
use HyperfExt\Jwt\Providers\NativeJwtProvider;
use HyperfExt\Jwt\Signers\Factory as SignerFactory;

/**
 * Builds {@see JWT} instances from the application's `jwt` configuration.
 *
 * Each scene is materialised lazily and cached by {@see JwtManager}.
 *
 * The dependency chain follows the tymon/jwt-auth architecture:
 *
 *     JWT extends Manager
 *         ├── JWTProvider (NativeJwtProvider — signing + base64url)
 *         ├── PayloadFactory (→ ClaimFactory)
 *         ├── PayloadValidator
 *         └── Blacklist (→ BlacklistStorage → PSR-16 Cache)
 */
class JwtFactory
{
    public function __construct(
        protected ContainerInterface $container,
        protected SignerFactory $signerFactory
    ) {
    }

    /**
     * Create a JWT instance bound to the given (or default) scene.
     */
    public function make(?string $scene = null): JWT
    {
        $config = $this->container->get(ConfigInterface::class);
        $scene ??= (string) $config->get('jwt.default', 'default');

        $sceneConfig = (array) $config->get('jwt.scenes.' . $scene, []);

        if ($sceneConfig === []) {
            throw new \InvalidArgumentException(sprintf('JWT scene [%s] is not configured.', $scene));
        }

        // Build the low-level JWT provider (signing + base64url + JSON).
        $provider = new NativeJwtProvider($this->signerFactory, $sceneConfig);

        // Normalise claims config: convert top-level `ttl` (minutes) to
        // `claims.exp` (seconds) if not explicitly set in claims.
        $claimsConfig = (array) ($sceneConfig['claims'] ?? []);
        if (! isset($claimsConfig['exp'])) {
            $claimsConfig['exp'] = (int) ($sceneConfig['ttl'] ?? 60) * 60;
        }

        // Build the claim factory + payload factory.
        $claimFactory = new ClaimFactory(
            $claimsConfig,
            (int) ($sceneConfig['leeway'] ?? 0)
        );
        $payloadFactory = new PayloadFactory($claimFactory);
        $payloadFactory->setClaimConfig($claimsConfig);

        // Build the validator.
        $validator = new PayloadValidator();

        // Build the blacklist (or null when disabled / unavailable).
        $blacklist = $this->buildBlacklist($sceneConfig);

        // Merge the normalised claims back into sceneConfig so that Manager's
        // setConfig() propagates the correct exp TTL to all sub-components.
        $sceneConfig['claims'] = $claimsConfig;

        // Assemble the JWT instance (extends Manager).
        return new JWT($provider, $payloadFactory, $validator, $blacklist, $sceneConfig);
    }

    /**
     * Construct the blacklist (or null when disabled / unavailable).
     */
    protected function buildBlacklist(array $sceneConfig): ?Blacklist
    {
        if (! ($sceneConfig['blacklist_enabled'] ?? true)) {
            return null;
        }

        $config = $this->container->get(ConfigInterface::class);
        $storageConfig = (array) $config->get('jwt.blacklist_storage', []);

        $driver = $storageConfig['driver'] ?? 'default';
        $prefix = $storageConfig['prefix'] ?? 'jwt:blacklist:';

        try {
            $cache = $this->container->get(CacheFactory::class)->get((string) $driver);
        } catch (\Throwable $e) {
            // If the cache driver cannot be resolved, fall back to disabling
            // the blacklist rather than crashing the whole auth stack.
            return (new Blacklist(new BlacklistStorage(new class implements \Psr\SimpleCache\CacheInterface {
                // Minimal no-op cache fallback.
                public function get(string $key, mixed $default = null): mixed { return $default; }
                public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool { return false; }
                public function delete(string $key): bool { return false; }
                public function clear(): bool { return false; }
                public function getMultiple(iterable $keys, mixed $default = null): iterable { return []; }
                public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool { return false; }
                public function deleteMultiple(iterable $keys): bool { return false; }
                public function has(string $key): bool { return false; }
            }, $prefix)))->setEnabled(false);
        }

        $storage = new BlacklistStorage($cache, $prefix);

        return new Blacklist(
            $storage,
            (int) ($sceneConfig['blacklist_grace_period'] ?? 0),
            (int) ($sceneConfig['blacklist_storage_ttl'] ?? 20160),
            true
        );
    }
}
