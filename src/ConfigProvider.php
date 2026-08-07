<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Hyperf\Contract\ContainerInterface;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                // Injecting JWTInterface yields the default-scene instance.
                Contracts\JWTInterface::class => function (ContainerInterface $c) {
                    return $c->get(JwtManager::class)->default();
                },
                Signers\Factory::class => Signers\Factory::class,
                JwtFactory::class => JwtFactory::class,
                JwtManager::class => JwtManager::class,
            ],
            'listeners' => [],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The configuration for hyperf-ext/jwt.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => BASE_PATH . '/config/autoload/jwt.php',
                ],
            ],
        ];
    }
}
