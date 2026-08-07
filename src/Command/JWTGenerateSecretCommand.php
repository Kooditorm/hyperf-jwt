<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt\Command;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputOption;

#[Command]
class JWTGenerateSecretCommand extends HyperfCommand
{
    protected ContainerInterface $container;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        parent::__construct('jwt:secret');
    }

    public function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate a random JWT secret key')
            ->addOption(
                'show',
                's',
                InputOption::VALUE_NONE,
                'Display the secret instead of writing to .env file'
            )
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Force overwriting an existing secret in the .env file'
            );
    }

    public function handle(): void
    {
        $key = $this->generateRandomKey();

        if ($this->input->getOption('show')) {
            $this->info($key);
            return;
        }

        $envPath = BASE_PATH . '/.env';

        if (! file_exists($envPath)) {
            $this->error('.env file not found. Please create one first.');
            $this->info('Your JWT secret: ' . $key);
            return;
        }

        $contents = file_get_contents($envPath);

        if (str_contains($contents, 'JWT_SECRET=')) {
            if ($this->input->getOption('force')) {
                $contents = preg_replace(
                    '/^JWT_SECRET=.*$/m',
                    'JWT_SECRET=' . $key,
                    $contents
                );
                file_put_contents($envPath, $contents);
                $this->info('JWT secret updated successfully.');
            } else {
                $this->warn('JWT_SECRET already exists in .env file. Use --force to overwrite.');
                $this->info('New secret (not saved): ' . $key);
            }
        } else {
            file_put_contents($envPath, $contents . "\nJWT_SECRET=" . $key . "\n");
            $this->info('JWT secret added to .env file.');
        }
    }

    protected function generateRandomKey(): string
    {
        return bin2hex(random_bytes(32));
    }
}
