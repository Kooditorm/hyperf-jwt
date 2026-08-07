<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Tests;

use HyperfExt\Jwt\Contracts\SignerInterface;
use HyperfExt\Jwt\Exceptions\JWTException;
use HyperfExt\Jwt\Signers\ES256;
use HyperfExt\Jwt\Signers\ES384;
use HyperfExt\Jwt\Signers\HS256;
use HyperfExt\Jwt\Signers\RS256;
use HyperfExt\Jwt\Signers\Factory as SignerFactory;

class SignersTest extends TestCase
{
    public function testFactoryCreatesEveryBuiltinAlgorithm(): void
    {
        $factory = new SignerFactory();

        foreach (['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384'] as $algo) {
            $signer = $factory->create($algo, 'secret');
            $this->assertInstanceOf(SignerInterface::class, $signer);
            $this->assertSame($algo, $signer->getAlgorithm());
        }
    }

    public function testFactoryRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(JWTException::class);
        (new SignerFactory())->create('NONE', 'secret');
    }

    public function testHmacSignAndVerify(): void
    {
        $signer = new HS256('my-shared-secret');
        $payload = 'header.payload';

        $signature = $signer->sign($payload);

        $this->assertTrue($signer->verify($signature, $payload));
        $this->assertFalse($signer->verify($signature, 'tampered'));
    }

    public function testHmacRequiresSecret(): void
    {
        $this->expectException(JWTException::class);
        (new HS256(''))->sign('payload');
    }

    public function testRsaSignAndVerify(): void
    {
        [$public, $private] = $this->generateRsaKeyPair();

        $signer = new RS256('', $public, $private);
        $payload = 'header.payload';

        $signature = $signer->sign($payload);

        $this->assertTrue($signer->verify($signature, $payload));
        $this->assertFalse($signer->verify($signature, 'tampered'));
    }

    public function testEcdsa256ProducesFixedLengthSignature(): void
    {
        [$public, $private] = $this->generateEcKeyPair('prime256v1');

        $signer = new ES256('', $public, $private);
        $payload = 'header.payload';

        $signature = $signer->sign($payload);

        // R(32) || S(32) = 64 bytes, per JOSE.
        $this->assertSame(64, strlen($signature));
        $this->assertTrue($signer->verify($signature, $payload));
        $this->assertFalse($signer->verify($signature, 'tampered'));
    }

    public function testEcdsa384ProducesFixedLengthSignature(): void
    {
        [$public, $private] = $this->generateEcKeyPair('secp384r1');

        $signer = new ES384('', $public, $private);
        $payload = 'header.payload';

        $signature = $signer->sign($payload);

        // R(48) || S(48) = 96 bytes.
        $this->assertSame(96, strlen($signature));
        $this->assertTrue($signer->verify($signature, $payload));
    }

    /**
     * Resolve the openssl.cnf path bundled with the PHP binary.
     * Needed by openssl_pkey_new/export on Windows portable builds.
     */
    protected function opensslConfig(): ?string
    {
        $candidate = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras'
            . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';

        return is_file($candidate) ? $candidate : null;
    }

    /**
     * @return array{0:string,1:string}
     */
    protected function generateRsaKeyPair(): array
    {
        $config = $this->opensslConfig();
        $args = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        if ($config !== null) {
            $args['config'] = $config;
        }

        $res = openssl_pkey_new($args);
        openssl_pkey_export($res, $private, null, $config !== null ? ['config' => $config] : []);
        $public = openssl_pkey_get_details($res)['key'];

        return [$public, $private];
    }

    /**
     * @return array{0:string,1:string}
     */
    protected function generateEcKeyPair(string $curve): array
    {
        // PHP's openssl_pkey_new() reads `curve_name` from the OpenSSL config
        // for EC keys. Write a temporary config so the curve can be parameterised.
        $tmpCnf = tempnam(sys_get_temp_dir(), 'jwt_ec_');
        file_put_contents($tmpCnf, "[ec]\ncurve_name = {$curve}\n");

        try {
            $res = @openssl_pkey_new([
                'config' => $tmpCnf,
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'ec_curve_name' => $curve,
            ]);

            // Some Windows + OpenSSL 3.x builds cannot generate EC keys without
            // extra provider configuration. Skip gracefully in that case.
            if (! $res) {
                $this->markTestSkipped(sprintf(
                    'Cannot generate an EC key on this platform (OpenSSL %s): %s',
                    OPENSSL_VERSION_TEXT,
                    openssl_error_string() ?: 'unknown error'
                ));
            }

            openssl_pkey_export($res, $private, null, ['config' => $tmpCnf]);
            $public = openssl_pkey_get_details($res)['key'];

            return [$public, $private];
        } finally {
            @unlink($tmpCnf);
        }
    }
}
