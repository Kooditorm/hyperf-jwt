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
use Kooditorm\Hyperf\Auth\AuthManager;
use Kooditorm\Hyperf\Auth\Contracts\Access\GateManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;
use Kooditorm\Hyperf\Auth\Contracts\PasswordBrokerManagerInterface;
use Kooditorm\Hyperf\Auth\Passwords\PasswordBrokerManager;
use Kooditorm\Hyperf\Hash\Contract\HashInterface;
use Kooditorm\Hyperf\Hash\HashManager;
use Kooditorm\Hyperf\Jwt\Commands\GenJwtSecretCommand;
use Kooditorm\Hyperf\Jwt\Contracts\JwtFactoryInterface;
use Kooditorm\Hyperf\Jwt\Contracts\ManagerInterface;
use Kooditorm\Hyperf\Jwt\Contracts\PayloadValidatorInterface;
use Kooditorm\Hyperf\Jwt\Contracts\RequestParser\RequestParserInterface;
use Kooditorm\Hyperf\Jwt\Contracts\TokenValidatorInterface;
use Kooditorm\Hyperf\Jwt\JwtFactory;
use Kooditorm\Hyperf\Jwt\ManagerFactory;
use Kooditorm\Hyperf\Jwt\RequestParser\RequestParserFactory;
use Kooditorm\Hyperf\Jwt\Validators\PayloadValidator;
use Kooditorm\Hyperf\Jwt\Validators\TokenValidator;


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
                ManagerInterface::class => ManagerFactory::class,
                TokenValidatorInterface::class => TokenValidator::class,
                PayloadValidatorInterface::class => PayloadValidator::class,
                RequestParserInterface::class => RequestParserFactory::class,
                JwtFactoryInterface::class => JwtFactory::class
            ],
            'commands' => [
                GenJwtSecretCommand::class
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
                    'id' => 'config.hash',
                    'description' => 'The config for Kooditorm/Hyperf-jwt/hash package.',
                    'source' => __DIR__ . '/../publish/hash.php',
                    'destination' => BASE_PATH . '/config/autoload/hash.php',
                ],
                [
                    'id' => 'config.auth',
                    'description' => 'The config for Kooditorm/Hyperf-jwt/auth package.',
                    'source' => __DIR__ . '/../publish/auth.php',
                    'destination' => BASE_PATH . '/config/autoload/auth.php',
                ],
                [
                    'id' => 'config.jwt',
                    'description' => 'The config for Kooditorm/Hyperf-jwt/jwt package.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => BASE_PATH . '/config/autoload/jwt.php',
                ]
            ]
        ];
    }
}