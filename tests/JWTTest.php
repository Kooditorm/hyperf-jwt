<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Tests;

use HyperfExt\Jwt\Contracts\JWTSubject;
use HyperfExt\Jwt\Exceptions\JWTException;
use HyperfExt\Jwt\Exceptions\SignatureInvalidException;
use HyperfExt\Jwt\Exceptions\TokenBlacklistedException;
use HyperfExt\Jwt\Exceptions\TokenExpiredException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use HyperfExt\Jwt\Exceptions\TokenNotYetValidException;
use HyperfExt\Jwt\PayloadFactory;
use HyperfExt\Jwt\Support\CustomClaims;
use HyperfExt\Jwt\Token;

/**
 * End-to-end tests for the JWT service (HS256, in-memory blacklist).
 *
 * Tests the full tymon-style stack:
 *   JWT (extends Manager) → NativeJwtProvider + PayloadFactory + Blacklist
 */
class JWTTest extends TestCase
{
    // ─── Basic encode / decode ──────────────────────────────────────────────

    public function testEncodeProducesTokenWithThreeSegments(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => 'user-1']);

        $this->assertInstanceOf(Token::class, $token);
        $this->assertCount(3, explode('.', $token->get()));
    }

    public function testEncodeAndDecodeRoundTrip(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => 'user-1', 'role' => 'admin']);

        $claims = $jwt->decode($token)->toArray();

        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame('admin', $claims['role']);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('jti', $claims);
    }

    public function testTokenStringConversion(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        $this->assertSame($token->get(), (string) $token);
    }

    // ─── Error handling ─────────────────────────────────────────────────────

    public function testDecodeMalformedTokenThrows(): void
    {
        $jwt = $this->makeJwt();

        $this->expectException(TokenInvalidException::class);
        $jwt->decode('not.a.valid.token');
    }

    public function testDecodeWithBadSignatureThrows(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        [$h, $p] = explode('.', $token->get());
        $tampered = $h . '.' . $p . '.' . str_repeat('A', 43);

        $this->expectException(SignatureInvalidException::class);
        $jwt->decode($tampered);
    }

    public function testDecodeWrongSecretThrows(): void
    {
        $jwtA = $this->makeJwt(['secret' => 'secret-a']);
        $jwtB = $this->makeJwt(['secret' => 'secret-b']);

        $token = $jwtA->encodeFromClaims(['sub' => '1']);

        $this->expectException(SignatureInvalidException::class);
        $jwtB->decode($token);
    }

    // ─── Time-based claims ──────────────────────────────────────────────────

    public function testExpiredTokenThrows(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['exp' => time() - 10]);

        $this->expectException(TokenExpiredException::class);
        $jwt->decode($token);
    }

    public function testLeewayAllowsSlightlyExpiredToken(): void
    {
        $jwt = $this->makeJwt(['leeway' => 60]);
        $token = $jwt->encodeFromClaims(['exp' => time() - 5]);

        $claims = $jwt->decode($token)->toArray();
        $this->assertNotEmpty($claims);
    }

    public function testNotBeforeInFutureThrows(): void
    {
        $jwt = $this->makeJwt(['claims' => ['exp' => 3600, 'nbf' => 300, 'jti' => true]]);
        $token = $jwt->encodeFromClaims();

        $this->expectException(TokenNotYetValidException::class);
        $jwt->decode($token);
    }

    // ─── Claim validation ───────────────────────────────────────────────────

    public function testIssuerMismatchThrows(): void
    {
        $jwt = $this->makeJwt(['claims' => ['exp' => 3600, 'jti' => true, 'iss' => 'app']]);
        $token = $jwt->encodeFromClaims();

        $other = $this->makeJwt(['claims' => ['exp' => 3600, 'jti' => true, 'iss' => 'other']]);
        $this->expectException(TokenInvalidException::class);
        $other->decode($token);
    }

    public function testAudienceMismatchThrows(): void
    {
        $jwt = $this->makeJwt(['claims' => ['exp' => 3600, 'jti' => true, 'aud' => 'api']]);
        $token = $jwt->encodeFromClaims();

        $other = $this->makeJwt(['claims' => ['exp' => 3600, 'jti' => true, 'aud' => 'web']]);
        $this->expectException(TokenInvalidException::class);
        $other->decode($token);
    }

    // ─── Refresh + blacklist ────────────────────────────────────────────────

    public function testRefreshIssuesNewTokenAndBlacklistsOld(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => 'user-1']);

        $refreshed = $jwt->refresh($token);

        $this->assertInstanceOf(Token::class, $refreshed);
        $this->assertNotSame($token->get(), $refreshed->get());

        $this->expectException(TokenBlacklistedException::class);
        $jwt->decode($token);
    }

    public function testInvalidateAddsTokenToBlacklist(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        $this->assertTrue($jwt->invalidate($token));

        $this->expectException(TokenBlacklistedException::class);
        $jwt->decode($token);
    }

    public function testValidateReturnsBool(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        $this->assertTrue($jwt->validate($token));
        $this->assertFalse($jwt->validate('garbage'));
    }

    public function testPayloadWithoutValidation(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        $claims = $jwt->payload($token)->toArray();
        $this->assertSame('1', $claims['sub']);
    }

    public function testCustomClaimsArePreservedOnRefresh(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => 'user-9', 'scope' => 'read']);

        $refreshed = $jwt->decode($jwt->refresh($token))->toArray();

        $this->assertSame('user-9', $refreshed['sub']);
        $this->assertSame('read', $refreshed['scope']);
    }

    public function testBlacklistGracePeriodKeepsTokenValid(): void
    {
        $jwt = $this->makeJwt(['blacklist_grace_period' => 3600]);
        $token = $jwt->encodeFromClaims(['sub' => '1']);

        $jwt->invalidate($token);

        $this->assertTrue($jwt->validate($token));
    }

    // ─── tymon-style auth API ───────────────────────────────────────────────

    public function testFromSubjectCreatesTokenWithSubClaim(): void
    {
        $jwt = $this->makeJwt();
        $subject = new TestUser(42, ['role' => 'admin']);

        $token = $jwt->fromSubject($subject);

        $this->assertInstanceOf(Token::class, $token);

        $claims = $jwt->decode($token)->toArray();
        $this->assertSame(42, $claims['sub']);
        $this->assertSame('admin', $claims['role']);
    }

    public function testParseTokenSetsTokenState(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '7']);

        $result = $jwt->parseToken('Bearer ' . $token->get());

        $this->assertSame($jwt, $result);
        $this->assertInstanceOf(Token::class, $jwt->getToken());
        $this->assertSame($token->get(), $jwt->getToken()->get());
    }

    public function testParseTokenReturnsFalseWhenEmpty(): void
    {
        $jwt = $this->makeJwt();

        $this->assertFalse($jwt->parseToken(''));
        $this->assertFalse($jwt->parseToken(null));
    }

    public function testGetPayloadReturnsDecodedPayload(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => '99']);

        $jwt->setToken($token);

        $payload = $jwt->getPayload();

        $this->assertSame('99', $payload['sub']);
        $this->assertArrayHasKey('exp', $payload->toArray());
    }

    public function testSubjectResolverReturnsUser(): void
    {
        $jwt = $this->makeJwt();
        $token = $jwt->encodeFromClaims(['sub' => 42]);

        $jwt->setSubjectResolver(function ($id) {
            return new TestUser($id, []);
        });

        $jwt->setToken($token);
        $user = $jwt->subject();

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame(42, $user->getJWTIdentifier());
    }

    public function testGetPayloadThrowsWithoutToken(): void
    {
        $jwt = $this->makeJwt();

        $this->expectException(JWTException::class);
        $jwt->getPayload();
    }

    // ─── PayloadFactory fluent API ──────────────────────────────────────────

    public function testPayloadFactoryFluentApi(): void
    {
        $jwt = $this->makeJwt();
        $factory = $jwt->getPayloadFactory();

        $payload = $factory
            ->sub(123)
            ->customClaims(['role' => 'admin'])
            ->setTTL(7200)
            ->make();

        $this->assertSame(123, $payload['sub']);
        $this->assertSame('admin', $payload['role']);
        $this->assertGreaterThan(time(), $payload['exp']);
        $this->assertLessThanOrEqual(time() + 7200, $payload['exp']);
    }

    public function testPayloadFactoryTtlOverride(): void
    {
        $jwt = $this->makeJwt();
        $factory = $jwt->getPayloadFactory();

        $payload = $factory->setTTL(1800)->make();

        $this->assertLessThanOrEqual(time() + 1800, $payload['exp']);
    }
}

/**
 * Simple JWTSubject implementation for testing.
 */
class TestUser implements JWTSubject
{
    use CustomClaims;

    public function __construct(
        protected int $id,
        protected array $customClaims
    ) {
    }

    public function getJWTIdentifier(): mixed
    {
        return $this->id;
    }

    public function getJWTCustomClaims(): array
    {
        return $this->customClaims;
    }
}
