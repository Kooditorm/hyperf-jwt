<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Signers;

use HyperfExt\Jwt\Exceptions\JWTException;

/**
 * ECDSA signer base (ES256 / ES384).
 *
 * OpenSSL produces ASN.1 DER signatures, but JWS (RFC 7515) requires the raw
 * R||S concatenation. We convert between the two representations.
 */
abstract class AbstractEcdsa extends AbstractSigner
{
    public function sign(string $payload): string
    {
        $key = $this->requirePrivateKey();
        $signature = '';

        if (! openssl_sign($payload, $signature, $key, $this->getHashAlgorithm())) {
            throw new JWTException(
                sprintf('OpenSSL failed to sign with %s: %s', $this->getAlgorithm(), openssl_error_string() ?: 'unknown error')
            );
        }

        return $this->asn1ToRaw($signature);
    }

    public function verify(string $expected, string $payload): bool
    {
        $key = $this->requirePublicKey();

        $asn1 = $this->rawToAsn1($expected);

        return openssl_verify($payload, $asn1, $key, $this->getHashAlgorithm()) === 1;
    }

    public function isAsymmetric(): bool
    {
        return true;
    }

    /**
     * The PHP hash algorithm name, e.g. `sha256`.
     */
    abstract protected function getHashAlgorithm(): string;

    /**
     * Byte-length of each ECDSA integer (R and S).
     * ES256 => 32, ES384 => 48.
     */
    abstract protected function getSignatureLength(): int;

    /**
     * Convert an ASN.1 DER signature into the raw R||S JOSE representation.
     */
    protected function asn1ToRaw(string $signature): string
    {
        // Minimal ASN.1 SEQUENCE parser.
        $pos = 0;
        $len = strlen($signature);

        if ($len < 2 || ord($signature[$pos]) !== 0x30) {
            throw new JWTException('Invalid ECDSA signature: expected ASN.1 SEQUENCE.');
        }
        ++$pos; // skip 0x30

        // Total length (handle short / long form).
        $totalLength = ord($signature[$pos]);
        ++$pos;
        if ($totalLength & 0x80) {
            $numBytes = $totalLength & 0x7f;
            $totalLength = 0;
            for ($i = 0; $i < $numBytes; ++$i) {
                $totalLength = ($totalLength << 8) | ord($signature[$pos]);
                ++$pos;
            }
        }

        // R INTEGER.
        if (ord($signature[$pos]) !== 0x02) {
            throw new JWTException('Invalid ECDSA signature: expected R INTEGER.');
        }
        ++$pos;
        $rLength = ord($signature[$pos]);
        ++$pos;
        $r = substr($signature, $pos, $rLength);
        $pos += $rLength;

        // S INTEGER.
        if (ord($signature[$pos]) !== 0x02) {
            throw new JWTException('Invalid ECDSA signature: expected S INTEGER.');
        }
        ++$pos;
        $sLength = ord($signature[$pos]);
        ++$pos;
        $s = substr($signature, $pos, $sLength);

        return $this->padToFixedLength($r) . $this->padToFixedLength($s);
    }

    /**
     * Convert a raw R||S JOSE signature into ASN.1 DER for OpenSSL.
     */
    protected function rawToAsn1(string $signature): string
    {
        $partLength = $this->getSignatureLength();

        if (strlen($signature) !== $partLength * 2) {
            throw new JWTException(sprintf(
                'Invalid raw ECDSA signature length: expected %d bytes, got %d.',
                $partLength * 2,
                strlen($signature)
            ));
        }

        $r = substr($signature, 0, $partLength);
        $s = substr($signature, $partLength);

        $r = $this->integerToDer($r);
        $s = $this->integerToDer($s);

        $body = "\x02" . chr(strlen($r)) . $r . "\x02" . chr(strlen($s)) . $s;

        return "\x30" . $this->lengthToDer(strlen($body)) . $body;
    }

    /**
     * Strip leading zeroes, then prepend a 0x00 if the high bit is set
     * (so the value is interpreted as positive by DER).
     */
    protected function integerToDer(string $value): string
    {
        $value = ltrim($value, "\x00");

        if ($value === '') {
            $value = "\x00";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return $value;
    }

    /**
     * Encode an ASN.1 length in short or long form.
     */
    protected function lengthToDer(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Left-pad (or trim) an integer to the fixed curve width.
     */
    protected function padToFixedLength(string $value): string
    {
        $length = $this->getSignatureLength();
        $value = ltrim($value, "\x00");

        return str_pad($value, $length, "\x00", STR_PAD_LEFT);
    }
}
