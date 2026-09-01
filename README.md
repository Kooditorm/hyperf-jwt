# Kooditorm/Hyperf-JWT

> JSON Web Token Authentication for Hyperf, adapted from [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth).

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.0-blue)](composer.json)

一个面向 [Hyperf](https://hyperf.io/) 框架的 JSON Web Token 认证组件，除了 JWT 签发/解析/刷新/黑名单等核心能力外，还内置了完整的 **Auth 认证**、**Gate 授权**、**密码重置** 与 **Hash 哈希** 体系。

## 目录

- [特性](#特性)
- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
  - [jwt.php](#jwtphp)
  - [auth.php](#authphp)
  - [hash.php](#hashphp)
- [快速开始](#快速开始)
- [JWT 模块](#jwt-模块)
  - [签发 Token](#签发-token)
  - [解析与校验](#解析与校验)
  - [刷新与注销](#刷新与注销)
  - [自定义 Claims](#自定义-claims)
  - [Token 请求来源](#token-请求来源)
  - [黑名单](#黑名单)
- [Auth 模块](#auth-模块)
  - [守卫（Guards）](#守卫guards)
  - [用户提供者（Providers）](#用户提供者providers)
  - [中间件](#中间件)
  - [注解鉴权](#注解鉴权)
  - [Gate 授权](#gate-授权)
  - [密码重置](#密码重置)
  - [事件](#事件)
- [Hash 模块](#hash-模块)
- [命令](#命令)
- [异常](#异常)
- [契约（Contracts）](#契约contracts)
- [目录结构](#目录结构)
- [License](#license)

## 特性

- 基于 [lcobucci/jwt](https://github.com/lcobucci/jwt) 4.x，支持 HS256/384/512、RS256/384/512、ES256/384/512 多种算法
- Token 全生命周期管理：签发、解析、刷新、加入黑名单
- 内置黑名单机制，支持宽限期（grace period）与永久黑名单
- 从多种请求位置解析 Token：Header、Query、Body、路由参数、Cookie
- 完整认证体系：无状态 `JwtGuard` 与有状态 `TokenGuard`
- 用户提供者：模型（Model）与数据库（Database）两种驱动
- 注解鉴权 `@Auth` + AOP 实现声明式认证
- Gate 策略授权（`@Policy` 注解 + 配置注册）
- 密码重置（Password Broker）与令牌存储
- Bcrypt / Argon2i / Argon2id 哈希驱动
- 丰富的契约接口，全部组件可替换自定义实现

## 环境要求

- PHP >= 8.0
- Hyperf Framework ~3.1.0
- hyperf/cache（黑名单默认存储依赖）

## 安装

```bash
composer require kooditorm/hyperf-jwt
```

发布配置文件（生成 `config/autoload/jwt.php`、`auth.php`、`hash.php`）：

```bash
# 发布全部配置
php bin/hyperf.php vendor:publish kooditorm/hyperf-jwt

# 或按 id 单独发布
php bin/hyperf.php vendor:publish --id=config.jwt
php bin/hyperf.php vendor:publish --id=config.auth
php bin/hyperf.php vendor:publish --id=config.hash
```

生成 JWT 密钥（写入项目根目录 `.env` 的 `JWT_SECRET`）：

```bash
php bin/hyperf.php gen:jwt-secret
```

> 也可手动生成：`echo base64_encode(random_bytes(64));` 后填入 `.env` 的 `JWT_SECRET`。

## 配置

### jwt.php

```php
<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    | 对称算法（HS256/384/512）签名密钥，必须经 base64 编码。
    | 可通过 `php bin/hyperf.php gen:jwt-secret` 生成。
    |
    */
    'secret' => env('JWT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Keys
    |--------------------------------------------------------------------------
    | 非对称算法（RS256/384/512、ES256/384/512）使用的密钥对。
    | public / private 为 PEM 证书内容，passphrase 为私钥口令（如需则 base64 编码）。
    |
    */
    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
        'passphrase' => env('JWT_PASSPHRASE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    | Token 有效时长（秒），默认 1 小时。
    | 设为 null 表示永不过期（需同步将 'exp' 从 required_claims 移除）。
    |
    */
    'ttl' => (int) env('JWT_TTL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Refresh time to live
    |--------------------------------------------------------------------------
    | Token 可被刷新的时间窗口（秒），默认 2 周。
    | 从签发时刻算起，超过该时间后不允许 refresh。
    |
    */
    'refresh_ttl' => (int) env('JWT_REFRESH_TTL', 3600 * 24 * 14),

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    | 可选：HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
    |
    */
    'algo' => env('JWT_ALGO', 'HS512'),

    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    | 解析 Token 时强制要求存在的 claim，缺失将抛出 TokenInvalidException。
    |
    */
    'required_claims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],

    /*
    |--------------------------------------------------------------------------
    | Persistent Claims
    |--------------------------------------------------------------------------
    | 刷新 Token 时需要保留的自定义 claim 键名（sub 与 iat 会自动保留）。
    |
    */
    'persistent_claims' => [
        // 'foo',
        // 'bar',
    ],

    /*
    |--------------------------------------------------------------------------
    | Lock Subject
    |--------------------------------------------------------------------------
    | 为 true 时自动添加 prv claim（subject 模型类名的 sha1 哈希），
    | 防止多个认证模型间 id 相同导致身份冒充。
    |
    */
    'lock_subject' => true,

    /*
    |--------------------------------------------------------------------------
    | Leeway
    |--------------------------------------------------------------------------
    | iat / nbf / exp 时间戳校验的容差（秒），用于缓解服务器时钟偏差。
    |
    */
    'leeway' => (int) env('JWT_LEEWAY', 0),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Enabled
    |--------------------------------------------------------------------------
    | 是否启用黑名单。关闭后 invalidate / refresh 将抛出 JwtException。
    |
    */
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Grace Period
    |--------------------------------------------------------------------------
    | 黑名单宽限期（秒）。刷新 Token 时旧 Token 在宽限期内仍可使用，
    | 避免并发请求中部分请求因 Token 已失效而失败。
    |
    */
    'blacklist_grace_period' => (int) env('JWT_BLACKLIST_GRACE_PERIOD', 0),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Storage
    |--------------------------------------------------------------------------
    | 黑名单存储驱动，需实现 Kooditorm\Hyperf\Jwt\Contracts\StorageInterface。
    | 默认基于 hyperf/cache（建议使用 Redis 驱动保证持久化）。
    |
    */
    'blacklist_storage' => Kooditorm\Hyperf\Jwt\Storage\HyperfCache::class,
];
```

### auth.php

```php
<?php

declare(strict_types=1);

return [
    // 默认守卫与默认密码重置配置
    'default' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],

    // 认证守卫
    'guards' => [
        // 有状态守卫：从 query / input / Bearer header / Basic auth 解析 token
        'web' => [
            'driver' => \Kooditorm\Hyperf\Auth\Guards\TokenGuard::class,
            'provider' => 'users',
            'options' => [],
        ],

        // 无状态守卫：基于 JWT，适用于 API
        'api' => [
            'driver' => \Kooditorm\Hyperf\Auth\Guards\JwtGuard::class,
            'provider' => 'users',
            'options' => [],
        ],
    ],

    // 用户提供者
    'providers' => [
        'users' => [
            'driver' => \Kooditorm\Hyperf\Auth\UserProviders\ModelUserProvider::class,
            'options' => [
                // 模型需实现 AuthenticatableInterface（可引入 Authenticatable trait）
                'model' => App\User::class,
                'hash_driver' => 'bcrypt',
            ],
        ],
        // 数据库驱动示例：
        // 'database' => [
        //     'driver' => \Kooditorm\Hyperf\Auth\UserProviders\DatabaseUserProvider::class,
        //     'options' => [
        //         'table' => 'users',
        //         'hash_driver' => 'bcrypt',
        //     ],
        // ],
    ],

    // 密码重置配置
    'passwords' => [
        'users' => [
            'driver' => \Kooditorm\Hyperf\Auth\Passwords\DatabaseTokenRepository::class,
            'provider' => 'users',
            'options' => [
                'connection' => null,          // 数据库连接名
                'table' => 'password_resets',  // 重置令牌表
                'expire' => 3600,              // 令牌有效期（秒）
                'throttle' => 60,              // 重试冷却（秒）
                'hash_driver' => null,         // 令牌哈希驱动，默认取 hash.default
            ],
        ],
    ],

    // 密码确认超时（秒），默认 3 小时
    'password_timeout' => 10800,

    // Gate 策略注册表：模型类 => 策略类
    'policies' => [
        // App\Model\User::class => App\Policy\UserPolicy::class,
    ],
];
```

### hash.php

```php
<?php

declare(strict_types=1);

return [
    // 默认哈希驱动
    'default' => 'bcrypt',

    'driver' => [
        // Bcrypt：rounds 为成本因子
        'bcrypt' => [
            'class' => \Kooditorm\Hyperf\Hash\Driver\BcryptDriver::class,
            'options' => [
                'rounds' => env('BCRYPT_ROUNDS', 10),
            ],
        ],

        // Argon2i：memory 内存（KB）、threads 线程数、time 迭代次数
        'argon2i' => [
            'class' => \Kooditorm\Hyperf\Hash\Driver\Argon2iDriver::class,
            'options' => [
                'memory' => 1024,
                'threads' => 2,
                'time' => 2,
            ],
        ],

        // Argon2id
        'argon2id' => [
            'class' => \Kooditorm\Hyperf\Hash\Driver\Argon2IdDriver::class,
            'options' => [
                'memory' => 1024,
                'threads' => 2,
                'time' => 2,
            ],
        ],
    ],
];
```

## 快速开始

1. 定义用户模型，实现 `AuthenticatableInterface` 与 `JwtSubjectInterface`（可引入两个 trait 减少样板代码）：

```php
<?php

namespace App\Model;

use Hyperf\DbConnection\Model\Model;
use Kooditorm\Hyperf\Auth\Authenticatable;
use Kooditorm\Hyperf\Auth\Contracts\AuthenticatableInterface;
use Kooditorm\Hyperf\Jwt\Contracts\JwtSubjectInterface;

/**
 * @property int $id
 * @property string $name
 * @property string $password
 */
class User extends Model implements AuthenticatableInterface, JwtSubjectInterface
{
    use Authenticatable;

    protected ?string $table = 'users';

    protected array $fillable = ['id', 'name', 'password'];

    protected array $hidden = ['password'];

    /**
     * 签发 JWT 时的 subject 标识（通常为主键）
     */
    public function getJwtIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * 签发 JWT 时附加的自定义 claim
     */
    public function getJwtCustomClaims(): array
    {
        return [];
    }
}
```

2. 登录接口（守卫签发 Token）：

```php
<?php

namespace App\Controller;

use Hyperf\Di\Annotation\Inject;
use Hyperf\HttpServer\Annotation\AutoController;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;

#[AutoController]
class AuthController
{
    #[Inject]
    protected AuthManagerInterface $auth;

    public function login(RequestInterface $request, ResponseInterface $response)
    {
        $credentials = $request->inputs(['email', 'password']);

        // 校验凭据，$login = true 时同时签发 Token 并建立登录态，返回 Token 字符串
        if (! $token = $this->auth->guard('api')->attempt($credentials, true)) {
            return $response->json(['error' => 'Unauthorized'], 401);
        }

        return $response->json(compact('token'));
    }

    public function me(ResponseInterface $response)
    {
        // 当前登录用户（JwtGuard 自动从请求解析 Token 并还原用户）
        $user = $this->auth->guard('api')->user();

        return $response->json($user);
    }
}
```

## JWT 模块

命名空间：`Kooditorm\Hyperf\Jwt`

核心类：
- `Jwt`：门面，封装全部常用操作
- `Manager`：Token 生命周期管理（编码、解码、刷新、注销）
- `Codec`：Token 编解码
- `Payload` / `Token`：载荷与令牌实体
- `Blacklist`：黑名单
- `PayloadFactory`：Payload 工厂
- `RequestParser`：从请求中解析 Token

依赖注入约定（由 `ConfigProvider` 注册）：

| 契约 | 默认实现 |
| --- | --- |
| `ManagerInterface` | `ManagerFactory` |
| `JwtFactoryInterface` | `JwtFactory` |
| `RequestParserInterface` | `RequestParserFactory` |
| `TokenValidatorInterface` | `TokenValidator` |
| `PayloadValidatorInterface` | `PayloadValidator` |
| `AuthManagerInterface` | `AuthManager` |
| `GateManagerInterface` | `GateManager` |
| `PasswordBrokerManagerInterface` | `PasswordBrokerManager` |
| `HashInterface` | `HashManager` |

### 签发 Token

```php
use Kooditorm\Hyperf\Jwt\Jwt;

$jwt = make(Jwt::class);

// 为实现了 JwtSubjectInterface 的用户签发 Token（返回字符串）
$token = $jwt->fromSubject($user);
$token = $jwt->fromUser($user); // 别名
```

### 解析与校验

```php
// 自动从请求中解析 Token（Header/Query/Body/路由参数/Cookie）
$payload = $jwt->checkOrFail();          // 校验失败抛出 JwtException 子类
$payload = $jwt->getPayload();           // 获取 Payload 实例
$payload = $jwt->getPayload(true);       // 忽略过期校验

$claim = $jwt->getClaim('sub');          // 获取单个 claim 值

$ok = $jwt->check();                     // bool
$payload = $jwt->check(true);            // 校验通过时返回 Payload，否则 false

$token = $jwt->getToken();               // 当前 Token 实例（可为 null）
$jwt->setToken('eyJ...');                // 手动指定 Token
$jwt->setRequest($request);              // 手动指定请求
$jwt->unsetToken();                      // 清除当前 Token
```

`Payload` 常用方法：

```php
$payload->get('sub');        // 取 claim 值
$payload->getSubject();      // 通过 __call 匹配 Claims\Subject，等价 get('sub')
$payload->getExpiration();   // 通过 __call 匹配 Claims\Expiration，返回 exp 值（时间戳）
$payload->toArray();         // 转为数组
$payload->toJson();          // 转为 JSON 字符串
$payload->hasKey('exp');     // 是否包含指定 claim
$payload->count();           // claim 数量
```

> `getSubject()`、`getExpiration()` 等 `getXxx()` 调用通过 `__call` 按名称匹配内置 Claim 类（`Claims\Subject`、`Claims\Expiration` 等），均返回对应 claim 的值。

### 刷新与注销

```php
// 刷新：旧 Token 自动加入黑名单，返回新 Token 字符串
$newToken = $jwt->refresh();

// 注销：将当前 Token 加入黑名单
$jwt->invalidate();

// 强制模式（forceForever）：忽略宽限期，立即生效
$jwt->refresh(true);
$jwt->invalidate(true);
```

> 黑名单被禁用（`blacklist_enabled = false`）时，`invalidate` 与 `refresh` 将抛出 `JwtException`：`You must have the blacklist enabled to invalidate a token.`

### 自定义 Claims

签发时附加自定义 claim：

```php
use Kooditorm\Hyperf\Jwt\Jwt;

$jwt = make(Jwt::class);

// 使用 CustomClaims trait 提供的方法（链式）
$token = $jwt->setCustomClaims(['role' => 'admin'])->fromSubject($user);

$jwt->setCustomClaims(['uid' => 10086]);
$token = $jwt->fromSubject($user);
```

也可以在模型 `getJwtCustomClaims()` 中返回默认自定义 claim：

```php
public function getJwtCustomClaims(): array
{
    return ['role' => 'admin'];
}
```

> 三个来源的合并优先级：`sub/prv` < 模型 `getJwtCustomClaims()` < `setCustomClaims()`（后者覆盖前者）。

### Token 请求来源

`RequestParser` 按固定优先级依次尝试以下来源（处理器位于 `Kooditorm\Hyperf\Jwt\RequestParser\Handlers`）：

1. `AuthHeaders` — `Authorization: Bearer <token>`
2. `QueryString` — `?token=<token>`
3. `InputSource` — 请求体字段 `token`
4. `RouteParams` — 路由参数 `token`
5. `Cookies` — Cookie 中的 `token`

可通过实现 `RequestParserInterface` 自定义解析逻辑。

### 黑名单

默认使用 `HyperfCache` 存储（基于 hyperf/cache，建议配置 Redis 驱动以持久化）。

```php
use Kooditorm\Hyperf\Jwt\Jwt;

$jwt = make(Jwt::class);

$blacklist = $jwt->getBlacklist();

$blacklist->add($payload);          // 将 payload 对应的 jti 加入黑名单（按 exp/refresh_ttl 自动过期）
$blacklist->addForever($payload);   // 永久加入黑名单
$blacklist->has($payload);          // 是否已被列入黑名单
$blacklist->remove($payload);       // 移除
$blacklist->clear();                // 清空全部
$blacklist->setGracePeriod(60);     // 设置宽限期（秒）
$blacklist->getGracePeriod();       // 获取宽限期
```

> 注意：`Blacklist` 的操作对象是 `Payload` 实例，不是 Token 字符串。

## Auth 模块

命名空间：`Kooditorm\Hyperf\Auth`

### 守卫（Guards）

守卫负责"当前请求中登录的是谁"的判定。内置两种守卫：

| 守卫 | 有状态 | 适用场景 | 配置 driver |
| --- | --- | --- | --- |
| `JwtGuard` | 否（Stateless） | API 接口，每次请求携带 JWT | `JwtGuard::class` |
| `TokenGuard` | 是（Stateful） | Web 场景，从请求中读取 token | `TokenGuard::class` |

```php
use Kooditorm\Hyperf\Auth\Contracts\AuthManagerInterface;

$auth = make(AuthManagerInterface::class);

$guard = $auth->guard('api');       // 获取指定守卫
$guard = $auth->guard();            // 默认守卫
$auth->shouldUse('api');            // 设置当前上下文默认守卫
$auth->setDefaultDriver('api');     // 修改全局默认守卫（config('auth.default.guard')）
```

`JwtGuard` 常用方法：

```php
$guard = $auth->guard('api');

$user  = $guard->user();                            // 当前登录用户（或 null）
$bool  = $guard->validate($credentials);            // 校验凭据但不登录
$bool  = $guard->once($credentials);                // 校验凭据并临时设置用户（不签发 Token）
$token = $guard->attempt($credentials, true);       // 校验凭据，通过则签发 Token 并登录；失败返回 false
$token = $guard->login($user);                      // 直接登录并签发 Token（用户需实现 JwtSubjectInterface）
$token = $guard->loginUsingId(1);                   // 按主键登录并签发 Token
$bool  = $guard->onceUsingId(1);                    // 按主键临时登录
$guard->logout(true);                               // 注销并将 Token 加入黑名单
$token = $guard->refresh(true);                     // 刷新 Token
$guard->invalidate(true);                           // 使当前 Token 失效
```

> `attempt()` 在 `$login = true` 时返回 Token 字符串，否则返回布尔值。

`TokenGuard` 常用方法：

```php
$guard = $auth->guard('web');

$user = $guard->user();               // 从 query/input/Bearer/Basic 中解析 token 并还原用户
$ok   = $guard->validate($credentials);
$bool = $guard->attempt($credentials);
$guard->login($user);                 // 记录登录态
$guard->logout();
```

`TokenGuard` 可配置项（`guards.web.options`）：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `input_key` | `api_token` | 从 query / input 中读取 token 的字段名 |
| `storage_key` | `api_token` | 用户表中存储 token 的字段名 |

### 用户提供者（Providers）

提供者负责按凭据从数据源检索用户：

| 提供者 | 说明 | 配置 driver |
| --- | --- | --- |
| `ModelUserProvider` | 基于 Hyperf 模型 | `ModelUserProvider::class` |
| `DatabaseUserProvider` | 基于数据库表 | `DatabaseUserProvider::class` |

```php
$provider = $auth->createUserProvider('users');

$user = $provider->retrieveById(1);
$user = $provider->retrieveByCredentials(['email' => 'a@b.com']);
$ok   = $provider->validateCredentials($user, ['password' => 'xxx']);
```

模型需实现 `AuthenticatableInterface`，可直接引入 `Kooditorm\Hyperf\Auth\Authenticatable` trait（提供 `getAuthIdentifierName/getAuthIdentifier/getAuthPassword/getRememberToken/setRememberToken` 等方法）。

### 中间件

内置抽象基类 `AbstractAuthenticateMiddleware`，只需实现 `guards()` 返回守卫名列表：

```php
<?php

namespace App\Middleware;

use Kooditorm\Hyperf\Auth\Middlewares\AbstractAuthenticateMiddleware;

class Authenticate extends AbstractAuthenticateMiddleware
{
    /**
     * 指定需要通过的守卫名称
     */
    protected function guards(): array
    {
        return ['api'];
    }
}
```

基类行为：
- `process()` 依次尝试 `guards()` 返回的守卫，任一守卫通过即放行
- 全部失败时调用 `unauthenticated()`，默认抛出 `AuthenticationException`（可覆盖 `redirectTo()` 自定义跳转）
- 覆盖 `passable()` 返回 `true` 可放行未认证请求

路由或控制器上启用：

```php
use App\Middleware\Authenticate;
use Hyperf\HttpServer\Annotation\AutoController;
use Hyperf\HttpServer\Annotation\Middleware;

#[AutoController]
#[Middleware(Authenticate::class)]
class UserController
{
}
```

### 注解鉴权

通过 AOP 实现声明式鉴权，无需手写中间件。注解类：`Kooditorm\Hyperf\Auth\Annotations\Auth`，由 `AuthAspect` 处理。

```php
use Hyperf\HttpServer\Annotation\AutoController;
use Kooditorm\Hyperf\Auth\Annotations\Auth;

/**
 * 控制器 / 方法上均可使用
 * @Auth(value={"api"})
 */
#[AutoController]
class UserController
{
    // 默认守卫（auth.default.guard）
    /**
     * @Auth
     */
    public function info() {}

    // 指定守卫
    /**
     * @Auth(value={"api", "web"})
     */
    public function detail() {}

    // 未认证也放行（passable）
    /**
     * @Auth(value={"api"}, passable=true)
     */
    public function guest() {}
}
```

> 注解参数约定（构造函数接收 `value` 数组）：
> - `value`：守卫名列表，缺省时使用默认守卫（`[null]`）
> - `passable`：默认 `false`，为 `true` 时未认证不抛异常
>
> 未认证访问会抛出 `AuthenticationException`（HTTP 401）。

### Gate 授权

Gate 用于"当前用户是否有权执行某操作"。入口为 `GateManager`（实现 `GateManagerInterface`），内部委托给 `Gate`。

1. 定义策略类：

```php
<?php

namespace App\Policy;

class PostPolicy
{
    public function update($user, $post): bool
    {
        return $user->id === $post->user_id;
    }
}
```

2. 注册策略（两种方式任选其一）：

方式一：`config/autoload/auth.php` 的 `policies` 中配置：

```php
'policies' => [
    App\Model\Post::class => App\Policy\PostPolicy::class,
],
```

方式二：使用 `@Policy` 注解自动注册：

```php
use Kooditorm\Hyperf\Auth\Annotations\Policy;

/**
 * @Policy(value={App\Model\Post::class})
 */
class PostPolicy
{
    // ...
}
```

3. 调用授权：

```php
use Kooditorm\Hyperf\Auth\Contracts\Access\GateManagerInterface;

$gate = make(GateManagerInterface::class);

$gate->allows('update', $post);                    // bool
$gate->denies('update', $post);                    // bool（取反）
$gate->check('update', $post);                     // bool
$gate->any(['update', 'delete'], $post);           // 任一通过
$gate->none(['update', 'delete'], $post);          // 全部拒绝
$gate->authorize('update', $post);                 // 拒绝时抛 AuthorizationException
$gate->forUser($user)->allows('update', $post);    // 指定用户判断

// 动态定义能力
$gate->define('update-post', fn ($user, $post) => $user->id === $post->user_id);

// 全局钩子
$gate->before(fn ($user, $ability) => $user->isAdmin() ? true : null);
$gate->after(fn ($user, $ability, $result) => $result);
```

### 密码重置

入口为 `PasswordBrokerManager`（实现 `PasswordBrokerManagerInterface`）：

```php
use Kooditorm\Hyperf\Auth\Contracts\PasswordBrokerManagerInterface;

$brokerManager = make(PasswordBrokerManagerInterface::class);
$broker = $brokerManager->broker('users');

// 发送重置链接（返回状态码）
$status = $broker->sendResetLink(['email' => 'a@b.com']);

// 重置密码（返回状态码）
$status = $broker->reset(
    ['email' => 'a@b.com', 'password' => 'new-pass', 'token' => 'reset-token'],
    function ($user, $password) {
        $user->password = password_hash($password, PASSWORD_BCRYPT);
        $user->save();
    }
);

// 校验重置令牌是否有效
$ok = $broker->tokenExists($user, 'reset-token');
```

> 使用前需创建 `password_resets` 表（`email`、`token`、`created_at`），且模型实现 `CanResetPasswordInterface`。
> `sendResetLink()` 会调用模型的 `sendPasswordResetNotification()` 发送重置通知；`reset()` 成功后触发 `PasswordReset` 事件。

### 事件

事件位于 `Kooditorm\Hyperf\Auth\Events`，可在 `config/autoload/listeners.php` 中注册监听器：

| 事件 | 说明 |
| --- | --- |
| `Attempting` | 守卫开始校验凭据时触发 |
| `Login` | 用户登录成功后触发 |
| `Logout` | 用户注销后触发 |
| `Authenticated` | 请求还原出已认证用户后触发 |
| `Failed` | 凭据校验失败时触发 |
| `Lockout` | 登录尝试被锁定时触发 |
| `CurrentDeviceLogout` | 当前设备注销时触发 |
| `OtherDeviceLogout` | 其他设备被注销时触发 |
| `Registered` | 用户注册时触发 |
| `Validated` | 凭据校验通过时触发 |
| `PasswordReset` | 密码重置成功时触发 |
| `AuthManagerResolved` | AuthManager 从容器解析后触发 |
| `GateManagerResolved` | GateManager 从容器解析后触发 |

监听器示例：

```php
<?php

namespace App\Listener;

use Hyperf\Event\Annotation\Listener;
use Hyperf\Event\Contract\ListenerInterface;
use Kooditorm\Hyperf\Auth\Events\Login;

#[Listener]
class LoginListener implements ListenerInterface
{
    public function listen(): array
    {
        return [Login::class];
    }

    public function process(object $event): void
    {
        // $event->user 为当前登录用户
    }
}
```

## Hash 模块

命名空间：`Kooditorm\Hyperf\Hash`。静态门面 `Hash`：

```php
use Kooditorm\Hyperf\Hash\Hash;

// 生成哈希
$hash = Hash::make('plain-password');
$hash = Hash::make('plain-password', ['rounds' => 12]);              // 指定 bcrypt rounds
$hash = Hash::make('plain-password', ['memory' => 2048], 'argon2i'); // 指定驱动及参数

// 校验
$ok = Hash::check('plain-password', $hash);
$ok = Hash::check('plain-password', $hash, [], 'argon2id');

// 是否需要重新哈希（哈希参数变更后返回 true）
$needs = Hash::needsRehash($hash);
$needs = Hash::needsRehash($hash, ['rounds' => 12], 'argon2i');

// 查看哈希信息（算法与参数）
$info = Hash::info($hash);

// 获取驱动实例（实现 DriverInterface）
$driver = Hash::getDriver('bcrypt');
```

可用驱动：

| 驱动 | 配置键 | 参数 |
| --- | --- | --- |
| `BcryptDriver` | `bcrypt` | `rounds` |
| `Argon2iDriver` | `argon2i` | `memory` / `threads` / `time` |
| `Argon2IdDriver` | `argon2id` | `memory` / `threads` / `time` |

> 自定义驱动需实现 `Kooditorm\Hyperf\Hash\Contract\DriverInterface`，并在 `hash.php` 的 `driver` 中注册 `class` 与 `options`。

## 命令

| 命令 | 说明 |
| --- | --- |
| `php bin/hyperf.php gen:jwt-secret` | 生成 64 字节随机密钥（base64 编码）并写入 `.env` 的 `JWT_SECRET` |

命令选项：

| 选项 | 说明 |
| --- | --- |
| `-s, --show` | 仅显示密钥，不修改文件 |
| `--always-no` | 密钥已存在时跳过，不覆盖 |
| `-f, --force` | 覆盖已存在密钥时跳过确认 |

## 异常

| 异常 | 抛出场景 |
| --- | --- |
| `JwtException`（基类） | JWT 通用错误：未提供 Token、黑名单未启用等 |
| `TokenExpiredException` | Token 已过期（`exp` 校验失败） |
| `TokenInvalidException` | Token 无效：签名错误、缺少必需 claim 等 |
| `TokenBlacklistedException` | Token 已被列入黑名单 |
| `AuthenticationException` | 认证失败（未登录、凭据错误等） |
| `AuthorizationException` | 授权失败（Gate 拒绝等） |

JWT 异常位于 `Kooditorm\Hyperf\Jwt\Exceptions`，Auth 异常位于 `Kooditorm\Hyperf\Auth\Exceptions`。

可在全局异常处理中统一捕获（`config/autoload/exceptions.php` 注册的处理器内）：

```php
use Kooditorm\Hyperf\Jwt\Exceptions\TokenExpiredException;
use Kooditorm\Hyperf\Jwt\Exceptions\TokenInvalidException;

public function handle(\Throwable $throwable, ResponseInterface $response)
{
    if ($throwable instanceof TokenExpiredException) {
        return $response->json(['error' => 'token expired'], 401);
    }
    if ($throwable instanceof TokenInvalidException) {
        return $response->json(['error' => 'token invalid'], 401);
    }
    // ...
}
```

## 契约（Contracts）

所有核心组件均以接口对外暴露，便于替换实现：

- `Kooditorm\Hyperf\Jwt\Contracts`：`ManagerInterface`、`CodecInterface`、`StorageInterface`、`RequestParserInterface`、`JwtSubjectInterface`、`JwtFactoryInterface`、`TokenValidatorInterface`、`PayloadValidatorInterface`、`ClaimInterface` 等
- `Kooditorm\Hyperf\Auth\Contracts`：`AuthManagerInterface`、`GuardInterface`、`StatefulGuardInterface`、`StatelessGuardInterface`、`UserProviderInterface`、`AuthenticatableInterface`、`CanResetPasswordInterface`、`PasswordBrokerInterface`、`PasswordBrokerManagerInterface`、`TokenRepositoryInterface`、`Access\GateManagerInterface` 等
- `Kooditorm\Hyperf\Hash\Contract`：`HashInterface`、`DriverInterface`

关键接口：

```php
// 可签发 JWT 的对象（如用户模型）
interface JwtSubjectInterface
{
    public function getJwtIdentifier(): mixed;   // subject 标识（通常返回主键）
    public function getJwtCustomClaims(): array; // 附加自定义 claim
}

// 可认证对象
interface AuthenticatableInterface
{
    public function getAuthIdentifierName(): string;
    public function getAuthIdentifier();          // 主键值
    public function getAuthPassword(): string;    // 密码字段值
    public function getRememberToken(): ?string;
    public function setRememberToken(?string $value);
    public function getRememberTokenName(): string;
}
```

## 目录结构

```
hyperf-jwt/
├── composer.json
├── LICENSE
├── publish/
│   ├── auth.php        # 守卫 / 提供者 / 密码重置 / Gate 策略配置
│   ├── hash.php        # 哈希驱动配置
│   └── jwt.php         # JWT 密钥 / 生命周期 / 黑名单配置
└── src/
    ├── ConfigProvider.php
    ├── Auth/
    │   ├── Access/                 # Gate / GateManager
    │   ├── Annotations/            # @Auth / @Policy 注解
    │   ├── Aspect/                 # AuthAspect（注解鉴权）
    │   ├── Contracts/              # 认证相关接口
    │   ├── Events/                 # 登录 / 注销 / 密码重置等事件
    │   ├── Exceptions/             # Authentication / AuthorizationException
    │   ├── Guards/                 # JwtGuard / TokenGuard
    │   ├── Middlewares/            # AbstractAuthenticateMiddleware
    │   ├── Passwords/              # PasswordBroker / DatabaseTokenRepository
    │   ├── UserProviders/          # ModelUserProvider / DatabaseUserProvider
    │   ├── Authenticatable.php     # 模型认证 trait
    │   ├── AuthManager.php
    │   ├── ContextHelpers.php
    │   ├── EventHelpers.php
    │   ├── GenericUser.php
    │   ├── GuardHelpers.php
    │   └── Recaller.php
    ├── Hash/
    │   ├── Contract/               # HashInterface / DriverInterface
    │   ├── Driver/                 # Bcrypt / Argon2i / Argon2Id 驱动
    │   ├── Hash.php                # 静态门面
    │   └── HashManager.php
    └── Jwt/
        ├── Claims/                 # iss / iat / exp / nbf / sub / jti / aud / custom
        ├── Commands/               # gen:jwt-secret 命令
        ├── Contracts/              # JWT 相关接口
        ├── Exceptions/             # Token 过期 / 无效 / 黑名单异常
        ├── RequestParser/          # 请求 Token 解析（Handlers 各来源）
        ├── Storage/                # HyperfCache 黑名单存储
        ├── Validators/             # TokenValidator / PayloadValidator
        ├── Blacklist.php
        ├── Codec.php
        ├── CustomClaims.php        # 自定义 claim trait
        ├── Jwt.php                 # 门面
        ├── JwtFactory.php
        ├── Manager.php             # Token 生命周期管理
        ├── ManagerFactory.php
        ├── Payload.php
        ├── PayloadFactory.php
        ├── Token.php
        └── Utils.php
```

## License

[MIT](LICENSE) © [Kooditorm](https://github.com/Kooditorm) / oswin.hu
