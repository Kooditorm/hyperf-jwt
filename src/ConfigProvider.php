<?php

declare(strict_types=1);

namespace Kooditorm\Hyperf\Jwt;

use Hyperf\Cache\Cache;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\ContainerInterface;
use Kooditorm\Hyperf\Jwt\Claims\Factory as ClaimFactory;
use Kooditorm\Hyperf\Jwt\Contracts\Http\Parser as ParserContract;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth as AuthContract;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\JWT as JWTContract;
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Storage as StorageContract;
use Kooditorm\Hyperf\Jwt\Http\Parser\AuthHeaders;
use Kooditorm\Hyperf\Jwt\Http\Parser\InputSource;
use Kooditorm\Hyperf\Jwt\Http\Parser\Parser;
use Kooditorm\Hyperf\Jwt\Http\Parser\QueryString;
use Kooditorm\Hyperf\Jwt\Providers\Auth\HyperfAuth;
use Kooditorm\Hyperf\Jwt\Providers\JWT\Lcobucci;
use Kooditorm\Hyperf\Jwt\Providers\Storage\HyperfCache;
use Kooditorm\Hyperf\Jwt\Validators\PayloadValidator;
use Kooditorm\Hyperf\Jwt\JWTGuard;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->dependencies(),
            'commands' => [
                Command\JWTGenerateSecretCommand::class,
            ],
            'annotations' => [],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config of hyperf-jwt.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => BASE_PATH . '/config/autoload/jwt.php',
                ],
            ],
        ];
    }

    public function dependencies(): array
    {
        return [
            JWTContract::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return new Lcobucci(
                    $config->get('jwt.secret'),
                    $config->get('jwt.algo', Lcobucci::ALGO_HS256),
                    [
                        'public' => $config->get('jwt.keys.public'),
                        'private' => $config->get('jwt.keys.private'),
                        'passphrase' => $config->get('jwt.keys.passphrase'),
                    ]
                );
            },

            AuthContract::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);
                return new HyperfAuth(
                    $container,
                    $config
                );
            },

            StorageContract::class => function (ContainerInterface $container) {
                return new HyperfCache($container->get(Cache::class));
            },

            PayloadValidator::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new PayloadValidator())
                    ->setRefreshTTL($config->get('jwt.refresh_ttl', 20160))
                    ->setRequiredClaims($config->get('jwt.required_claims', [
                        'iss', 'iat', 'exp', 'nbf', 'sub', 'jti',
                    ]));
            },

            ClaimFactory::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new ClaimFactory($container))
                    ->setTTL($config->get('jwt.ttl', 60))
                    ->setLeeway($config->get('jwt.leeway', 0))
                    ->setIssuer($config->get('jwt.iss'));
            },

            Factory::class => function (ContainerInterface $container) {
                return new Factory(
                    $container->get(ClaimFactory::class),
                    $container->get(PayloadValidator::class)
                );
            },

            Blacklist::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new Blacklist($container->get(StorageContract::class)))
                    ->setGracePeriod((int) $config->get('jwt.blacklist_grace_period', 0))
                    ->setRefreshTTL((int) $config->get('jwt.refresh_ttl', 20160));
            },

            Manager::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new Manager(
                    $container->get(JWTContract::class),
                    $container->get(Blacklist::class),
                    $container->get(Factory::class)
                ))
                    ->setBlacklistEnabled((bool) $config->get('jwt.blacklist_enabled', true))
                    ->setPersistentClaims($config->get('jwt.persistent_claims', []));
            },

            Parser::class => function (ContainerInterface $container) {
                return new Parser(null, [
                    new AuthHeaders(),
                    new QueryString(),
                    new InputSource(),
                ]);
            },

            JWT::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new JWT(
                    $container->get(Manager::class),
                    $container->get(Parser::class)
                ))->lockSubject((bool) $config->get('jwt.lock_subject', true));
            },

            JWTAuth::class => function (ContainerInterface $container) {
                $config = $container->get(ConfigInterface::class);

                return (new JWTAuth(
                    $container->get(Manager::class),
                    $container->get(AuthContract::class),
                    $container->get(Parser::class)
                ))->lockSubject((bool) $config->get('jwt.lock_subject', true));
            },

            'jwt.grard' => function () {
                return new JWTGuard();
            }
        ];
    }
}
