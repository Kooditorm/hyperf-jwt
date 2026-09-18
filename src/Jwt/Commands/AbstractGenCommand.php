<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf\Jwt\Commands;

use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Contract\ConfigInterface;
use Symfony\Component\Console\Input\InputOption;

class AbstractGenCommand extends HyperfCommand
{
    protected string $description = '';

    public function __construct(protected readonly ConfigInterface $config)
    {
        parent::__construct();
    }

    public function configure(): void
    {
        parent::configure();
        $this->setDescription($this->description);
        $this->addOption('show', 's', InputOption::VALUE_NONE, 'Display the key instead of modifying files');
        $this->addOption('always-no', null, InputOption::VALUE_NONE, 'Skip generating key if it already exists');
        $this->addOption('force', 'f', InputOption::VALUE_NONE, 'Skip confirmation when overwriting an existing key');
    }

    /**
     * @return mixed
     */
    protected function getOption(string $name, mixed $default = null)
    {
        $result = $this->input->getOption($name);

        return empty($result) ? $default : $result;
    }

    protected function envFilePath(): string
    {
        return BASE_PATH . '/.env';
    }
}
