<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Command;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * Generate a random HMAC secret and write it to the `.env` file.
 *
 * Equivalent to tymon/jwt-auth's `php artisan jwt:secret`.
 *
 * Usage:
 *   php bin/hyperf.php jwt:secret           # generate & write (prompts if exists)
 *   php bin/hyperf.php jwt:secret --force   # overwrite without prompting
 *   php bin/hyperf.php jwt:secret --show    # print the key, do not write
 */
#[Command]
class JwtSecretCommand extends HyperfCommand
{
    public function __construct(protected ContainerInterface $container)
    {
        parent::__construct('jwt:secret');
    }

    public function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate a JWT secret key for HMAC algorithms (HS256/HS384/HS512).')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Override the existing secret key.')
            ->addOption('show', 's', InputOption::VALUE_NONE, 'Display the key instead of writing to .env file.');
    }

    public function handle(): void
    {
        $key = $this->generateRandomKey();

        if ($this->input->getOption('show')) {
            $this->comment($key);

            return;
        }

        $path = $this->getEnvFilePath();

        if ($path === null) {
            $this->error('.env file not found. Create one first, or use --show to display the key.');

            return;
        }

        $content = (string) file_get_contents($path);
        $hasKey = (bool) preg_match('/^\s*JWT_SECRET\s*=/m', $content);

        if ($hasKey && ! $this->input->getOption('force')) {
            $answer = $this->confirm('JWT_SECRET already exists in .env. Do you want to override it?', false);

            if (! $answer) {
                $this->info('Operation cancelled.');

                return;
            }
        }

        $updated = $this->updateEnvFile($path, $content, $key, $hasKey);

        if ($updated) {
            $this->info('JWT secret key set successfully.');
        } else {
            $this->error('Failed to write to .env file.');
        }
    }

    /**
     * Generate a cryptographically secure 256-bit (32-byte) key, base64-encoded.
     */
    protected function generateRandomKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Resolve the `.env` file path relative to BASE_PATH (or CWD fallback).
     */
    protected function getEnvFilePath(): ?string
    {
        $basePath = defined('BASE_PATH') ? BASE_PATH : getcwd();
        $path = $basePath . '/.env';

        return file_exists($path) ? $path : null;
    }

    /**
     * Insert or replace the JWT_SECRET line in the .env file.
     */
    protected function updateEnvFile(string $path, string $content, string $key, bool $hasKey): bool
    {
        if ($hasKey) {
            // Replace the existing JWT_SECRET=... line.
            $content = (string) preg_replace(
                '/^\s*JWT_SECRET\s*=.*/m',
                'JWT_SECRET=' . $key,
                $content
            );
        } else {
            // Append a new line (ensure preceding newline).
            $content = rtrim($content, "\n") . "\n\nJWT_SECRET=" . $key . "\n";
        }

        return file_put_contents($path, $content) !== false;
    }
}
