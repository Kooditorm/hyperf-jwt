<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Tests;

use HyperfExt\Jwt\Blacklist\Blacklist;
use HyperfExt\Jwt\Blacklist\BlacklistStorage;
use HyperfExt\Jwt\Claims\Factory as ClaimFactory;
use HyperfExt\Jwt\JWT;
use HyperfExt\Jwt\Payload\PayloadValidator;
use HyperfExt\Jwt\PayloadFactory;
use HyperfExt\Jwt\Providers\NativeJwtProvider;
use HyperfExt\Jwt\Signers\Factory as SignerFactory;
use HyperfExt\Jwt\Tests\Support\ArrayCache;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected const SECRET = 'test-secret-key-for-phpunit-only-32bytes!!';

    /**
     * Build a JWT instance with an in-memory blacklist.
     *
     * Constructs the full tymon-style dependency chain:
     *   NativeJwtProvider → PayloadFactory → PayloadValidator → Blacklist → JWT(extends Manager)
     */
    protected function makeJwt(array $sceneOverrides = [], bool $withBlacklist = true): JWT
    {
        $scene = array_merge([
            'algo' => 'HS256',
            'secret' => self::SECRET,
            'keys' => [],
            'leeway' => 0,
            'ttl' => 60,
            'claims' => ['exp' => 3600, 'jti' => true],
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
            'blacklist_grace_period' => 0,
            'blacklist_storage_ttl' => 20160,
        ], $sceneOverrides);

        $signerFactory = new SignerFactory();

        // JWTProvider (low-level encode/decode engine).
        $provider = new NativeJwtProvider($signerFactory, $scene);

        // Claim factory + payload factory.
        $claimFactory = new ClaimFactory($scene['claims'], $scene['leeway']);
        $payloadFactory = new PayloadFactory($claimFactory);
        $payloadFactory->setClaimConfig($scene['claims']);

        // Validator.
        $validator = new PayloadValidator();

        // Blacklist.
        $blacklist = null;
        if ($withBlacklist) {
            $storage = new BlacklistStorage(new ArrayCache(), 'test:');
            $blacklist = new Blacklist($storage, $scene['blacklist_grace_period'], $scene['blacklist_storage_ttl'], true);
        }

        return new JWT($provider, $payloadFactory, $validator, $blacklist, $scene);
    }
}
