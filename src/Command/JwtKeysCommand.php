<?php

declare(strict_types=1);

namespace HyperfExt\Jwt\Command;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputOption;
use Throwable;

/**
 * Generate RSA or ECDSA key pairs for asymmetric JWT algorithms.
 *
 * Equivalent to running openssl from the CLI, but integrated into the
 * Hyperf command system so users get a single `php bin/hyperf.php jwt:keys`.
 *
 * Usage:
 *   php bin/hyperf.php jwt:keys                       # RSA 2048 → jwt-keys/
 *   php bin/hyperf.php jwt:keys --algo=ecdsa --bits=256
 *   php bin/hyperf.php jwt:keys --algo=rsa --bits=4096 --path=/data/keys
 *   php bin/hyperf.php jwt:keys --force               # overwrite existing files
 */
#[Command]
class JwtKeysCommand extends HyperfCommand
{
    public function __construct(protected ContainerInterface $container)
    {
        parent::__construct('jwt:keys');
    }

    public function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate RSA or ECDSA key pairs for asymmetric JWT algorithms (RS*, ES*).')
            ->addOption('algo', 'a', InputOption::VALUE_OPTIONAL, 'Algorithm: rsa or ecdsa', 'rsa')
            ->addOption('bits', 'b', InputOption::VALUE_OPTIONAL, 'Key size: 2048/4096 for RSA, 256/384 for ECDSA', '2048')
            ->addOption('path', 'p', InputOption::VALUE_OPTIONAL, 'Directory to store key files', '')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Overwrite existing key files.');
    }

    public function handle(): void
    {
        $algo = strtolower((string) $this->input->getOption('algo'));
        $bits = (int) $this->input->getOption('bits');
        $dir = (string) ($this->input->getOption('path') ?: $this->getDefaultKeyPath());

        if (! in_array($algo, ['rsa', 'ecdsa'], true)) {
            $this->error('Invalid algorithm. Use "rsa" or "ecdsa".');

            return;
        }

        // Validate bits per algorithm.
        if ($algo === 'rsa' && ! in_array($bits, [2048, 3072, 4096], true)) {
            $this->error('RSA key size must be 2048, 3072 or 4096.');

            return;
        }

        if ($algo === 'ecdsa' && ! in_array($bits, [256, 384], true)) {
            $this->error('ECDSA curve must be 256 (P-256) or 384 (P-384).');

            return;
        }

        // Prepare directory.
        if (! is_dir($dir)) {
            if (! @mkdir($dir, 0700, true)) {
                $this->error("Failed to create directory: {$dir}");

                return;
            }
        }

        $privatePath = $dir . '/jwt-' . $algo . '-private.pem';
        $publicPath = $dir . '/jwt-' . $algo . '-public.pem';

        // Check existing files.
        foreach ([$privatePath, $publicPath] as $file) {
            if (file_exists($file) && ! $this->input->getOption('force')) {
                $answer = $this->confirm("File exists: {$file}. Overwrite?", false);
                if (! $answer) {
                    $this->info('Operation cancelled.');

                    return;
                }
            }
        }

        try {
            if ($algo === 'rsa') {
                $this->generateRsaKeys($privatePath, $publicPath, $bits);
            } else {
                $this->generateEcdsaKeys($privatePath, $publicPath, $bits);
            }
        } catch (Throwable $e) {
            $this->error('Key generation failed: ' . $e->getMessage());

            return;
        }

        $this->info("{$algo} key pair generated:");
        $this->line("  Private: {$privatePath}");
        $this->line("  Public:  {$publicPath}");
        $this->newLine();
        $this->comment('Update your .env:');
        $envKey = strtoupper($algo);
        $this->line("  JWT_ALGO=" . ($algo === 'rsa' ? 'RS256' : 'ES256'));
        $this->line("  JWT_PUBLIC_KEY={$publicPath}");
        $this->line("  JWT_PRIVATE_KEY={$privatePath}");
    }

    protected function generateRsaKeys(string $privatePath, string $publicPath, int $bits): void
    {
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // Attempt to use the system openssl.cnf if available.
        $cnf = $this->findOpensslConfig();
        if ($cnf !== null) {
            $config['config'] = $cnf;
        }

        $res = openssl_pkey_new($config);
        if (! $res) {
            throw new \RuntimeException('openssl_pkey_new() failed for RSA. ' . openssl_error_string());
        }

        // Export private key (PKCS#8 PEM, no passphrase).
        openssl_pkey_export($res, $privatePem, null, $config);
        // Export public key.
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new \RuntimeException('openssl_pkey_get_details() failed.');
        }

        file_put_contents($privatePath, $privatePem);
        chmod($privatePath, 0600);
        file_put_contents($publicPath, $details['key']);
        chmod($publicPath, 0644);
    }

    protected function generateEcdsaKeys(string $privatePath, string $publicPath, int $bits): void
    {
        $curveName = match ($bits) {
            256 => 'prime256v1',
            384 => 'secp384r1',
            default => 'prime256v1',
        };

        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'ec_curve_name' => $curveName,
        ];

        // EC key generation requires a config file on some platforms.
        $cnf = $this->findOpensslConfig();
        if ($cnf !== null) {
            $config['config'] = $cnf;
        }

        $res = openssl_pkey_new($config);
        if (! $res) {
            // Fallback: create a temp config with ec section.
            $res = $this->generateEcKeyWithTempConfig($curveName);
            if (! $res) {
                throw new \RuntimeException(
                    'openssl_pkey_new() failed for ECDSA (curve: ' . $curveName . '). '
                    . 'On Windows you may need to set the OPENSSL_CONF environment variable. '
                    . (openssl_error_string() ?: '')
                );
            }
        }

        openssl_pkey_export($res, $privatePem, null, $config);
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new \RuntimeException('openssl_pkey_get_details() failed.');
        }

        file_put_contents($privatePath, $privatePem);
        chmod($privatePath, 0600);
        file_put_contents($publicPath, $details['key']);
        chmod($publicPath, 0644);
    }

    /**
     * Fallback EC key generation using a temporary openssl.cnf with [ec] section.
     */
    protected function generateEcKeyWithTempConfig(string $curveName): \OpenSSLAsymmetricKey|false
    {
        $tmpCnf = tempnam(sys_get_temp_dir(), 'jwt_ec_');
        if ($tmpCnf === false) {
            return false;
        }

        $cnfContent = "openssl_conf = openssl_init\n\n"
            . "[openssl_init]\n"
            . "providers = provider_sect\n\n"
            . "[provider_sect]\n"
            . "default = default_sect\n\n"
            . "[default_sect]\n"
            . "activate = 1\n\n"
            . "[ec]\n"
            . "curve_name = {$curveName}\n";

        file_put_contents($tmpCnf, $cnfContent);

        $res = openssl_pkey_new([
            'config' => $tmpCnf,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'ec_curve_name' => $curveName,
        ]);

        @unlink($tmpCnf);

        return $res;
    }

    /**
     * Try to locate the system openssl.cnf file.
     */
    protected function findOpensslConfig(): ?string
    {
        // 1. Environment variable.
        $env = getenv('OPENSSL_CONF');
        if ($env && file_exists($env)) {
            return $env;
        }

        // 2. PHP default.
        $default = openssl_get_default_cert_file();
        if ($default && file_exists($default)) {
            // The default file usually ends with cert.pem; the cnf is in the same dir.
            $dir = dirname($default);
            $candidates = [
                $dir . '/openssl.cnf',
                dirname($dir) . '/openssl.cnf',
            ];
            foreach ($candidates as $path) {
                if (file_exists($path)) {
                    return $path;
                }
            }
        }

        // 3. Common Windows locations relative to PHP binary.
        $phpDir = dirname(PHP_BINARY);
        $winCandidates = [
            $phpDir . '/extras/ssl/openssl.cnf',
            dirname($phpDir) . '/extras/ssl/openssl.cnf',
        ];
        foreach ($winCandidates as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }

    protected function getDefaultKeyPath(): string
    {
        $basePath = defined('BASE_PATH') ? BASE_PATH : getcwd();

        return $basePath . '/jwt-keys';
    }
}
