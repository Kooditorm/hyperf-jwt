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

use Kooditorm\Hyperf\Auth\Access\GateManager;
use Kooditorm\Hyperf\Auth\Contracts\Access\GateManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;
use Kooditorm\Hyperf\Auth\AuthManager;
use Kooditorm\Hyperf\Auth\Contracts\PasswordBrokerManagerInterface;
use Kooditorm\Hyperf\Auth\Passwords\PasswordBrokerManager;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;
use Kooditorm\Hyperf\Hash\HashManager;



class ConfigProvider
{

    public function __invoke(): array
    {
        return [
            'dependencies' => [
                HashInterface::class => HashManager::class,
                AuthManagerInterface::class => AuthManager::class,
                GateManagerInterface::class => GateManager::class,
                PasswordBrokerManagerInterface::class => PasswordBrokerManager::class,
            ],
            'commands' => [
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                    'ignore_annotations' => [
                        'mixin'
                    ]
                ]
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for Kooditorm/Hyperf-jwt/hash package.',
                    'source' => __DIR__ . '/../publish/hash.php',
                    'destination' => BASE_PATH . '/config/autoload/hash.php',
                ],
                [
                    'id' => 'config',
                    'description' => 'The config for Kooditorm/Hyperf-jwt/auth package.',
                    'source' => __DIR__ . '/../publish/auth.php',
                    'destination' => BASE_PATH . '/config/autoload/auth.php',
                ]
            ]
        ];
    }
}