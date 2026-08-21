<?php

declare(strict_types=1);

/**
 * This file is part of Kooditorm/hyperf-jwt.
 *
 * @link     https://github.com/Kooditorm/hyperf-jwt
 * @contact  oswin.hu@gmail.com
 * @license  https://github.com/Kooditorm/hyperf-jwt/blob/master/LICENSE
 */

namespace Kooditorm\Hyperf;

//use Kooditorm\Hyperf\Hash\Contracts\HashInterface;
//use Kooditorm\Hyperf\Hash\HashManager;

use Kooditorm\Hyperf\Hash\Contract\TestInterface;
use Kooditorm\Hyperf\Hash\TestManager;


class ConfigProvider
{

    public function __invoke(): array
    {
        return [
            'dependencies' => [
//                HashInterface::class => HashManager::class,
                TestInterface::class => TestManager::class,
            ],
            'commands' => [
            ],
            'annotations' => [],
//            'publish' => [
//                [
//                    'id' => 'config',
//                    'description' => 'The config for Kooditorm/Hyperf-jwt package.',
//                    'source' => __DIR__ . '/../publish/auth.php',
//                    'destination' => BASE_PATH . '/config/autoload/auth.php',
//                ]
//            ]
        ];
    }
}