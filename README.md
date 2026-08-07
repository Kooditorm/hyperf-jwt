# Kooditorm/hyperf-jwt

> 面向 Hyperf 3.1+ 的协程友好型 JWT 扩展包 —— 参考 tymon/jwt-auth 架构，支持多场景、黑名单吊销、刷新令牌与多种签名算法。

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.1-8892BF.svg)](https://www.php.net/)
[![Hyperf](https://img.shields.io/badge/Hyperf-3.1+-5059d8.svg)](https://hyperf.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 特性

- **tymon/jwt-auth 架构**：`Manager`（核心引擎）+ `JWTProvider`（编解码抽象）+ `PayloadFactory`（载荷工厂）+ `Token`（值对象）分层设计。
- **协程友好**：基于 Hyperf 缓存驱动实现黑名单，天然适配 Swoole / Swow 协程运行时。
- **多场景（Scene）**：一套配置管理多个独立的 JWT 上下文（如 `api`、`admin`、`app`），各自独立密钥 / 算法 / TTL。
- **JWTSubject 契约**：实现 `getJWTIdentifier()` / `getJWTCustomClaims()` 即可将用户模型与 JWT 打通。
- **完整算法支持**：HMAC（HS256/384/512）、RSA（RS256/384/512）、ECDSA（ES256/384），ECDSA 已处理 ASN.1 ↔ raw 签名格式转换。
- **黑名单吊销**：基于 `jti` 的令牌撤销机制，支持宽限期（grace period）。
- **刷新令牌**：在可配置的刷新窗口内用过期令牌换取新令牌，旧令牌自动入黑名单。
- **零外部 JWT 依赖**：签名与编解码全部基于 PHP 原生 `openssl` / `hash` 扩展。
- **开箱即用中间件**：`JwtAuthMiddleware`（认证）+ `RefreshMiddleware`（自动刷新）。

## 架构

```
JWT (extends Manager)
  ├── JWTProvider (NativeJwtProvider)    低层编解码 + 签名
  ├── PayloadFactory                      载荷工厂（默认声明 + 自定义声明）
  │     └── Claims\Factory               声明构造
  ├── PayloadValidator                    声明校验（exp/nbf/iat/iss/aud）
  └── Blacklist                           令牌吊销
        └── BlacklistStorage → PSR-16    缓存抽象

JwtManager                               多场景管理器
  └── JwtFactory                          从配置构建 JWT 实例
        └── JWT (per scene)
```

## 安装

```bash
composer require hyperf-ext/jwt
```

发布配置文件：

```bash
php bin/hyperf.php vendor:publish hyperf-ext/jwt
```

## 生成密钥

### HMAC 密钥（HS256/384/512）

```bash
# 生成随机密钥并写入 .env 的 JWT_SECRET=
php bin/hyperf.php jwt:secret

# 仅显示密钥不写入文件
php bin/hyperf.php jwt:secret --show

# 强制覆盖已有的 JWT_SECRET
php bin/hyperf.php jwt:secret --force
```

### RSA / ECDSA 密钥对（RS*/ES*）

```bash
# 生成 RSA 2048 密钥对（默认）
php bin/hyperf.php jwt:keys

# 生成 RSA 4096
php bin/hyperf.php jwt:keys --algo=rsa --bits=4096

# 生成 ECDSA P-256（对应 ES256）
php bin/hyperf.php jwt:keys --algo=ecdsa --bits=256

# 指定输出目录
php bin/hyperf.php jwt:keys --path=/data/jwt-keys

# 强制覆盖已有文件
php bin/hyperf.php jwt:keys --force
```

生成后命令会提示需要设置的 `.env` 变量：

```
JWT_ALGO=RS256
JWT_PUBLIC_KEY=/path/to/jwt-keys/jwt-rsa-public.pem
JWT_PRIVATE_KEY=/path/to/jwt-keys/jwt-rsa-private.pem
```

<details>
<summary>或使用 openssl 命令行手动生成</summary>

```bash
# RSA
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# ECDSA (P-256)
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

</details>

## 配置

```php
// config/autoload/jwt.php
return [
    'default' => env('JWT_DEFAULT_SCENE', 'default'),

    'scenes' => [
        'default' => [
            'secret' => env('JWT_SECRET', ''),
            'keys' => [
                'public'    => env('JWT_PUBLIC_KEY', ''),
                'private'   => env('JWT_PRIVATE_KEY', ''),
                'passphrase'=> env('JWT_PASSPHRASE', ''),
            ],
            'algo'        => env('JWT_ALGO', 'HS256'),
            'ttl'         => env('JWT_TTL', 60),        // 分钟
            'refresh_ttl' => env('JWT_REFRESH_TTL', 20160), // 分钟
            'leeway'      => env('JWT_LEEWAY', 0),       // 秒
            'claims' => [
                'iss' => env('JWT_ISS', null),
                'aud' => env('JWT_AUD', null),
                'nbf' => env('JWT_NBF', 0),
                'jti' => env('JWT_JTI', true),
            ],
            'blacklist_enabled'        => env('JWT_BLACKLIST_ENABLED', true),
            'blacklist_grace_period'   => env('JWT_BLACKLIST_GRACE', 0),
            'blacklist_storage_ttl'    => env('JWT_BLACKLIST_TTL', 20160),
        ],
    ],

    'blacklist_storage' => [
        'driver' => env('JWT_BLACKLIST_DRIVER', 'default'),
        'prefix' => env('JWT_BLACKLIST_PREFIX', 'jwt:blacklist:'),
    ],

    'providers' => [
        'jwt' => \HyperfExt\Jwt\Providers\NativeJwtProvider::class,
    ],
];
```

## 快速开始

### 基本用法

```php
use HyperfExt\Jwt\Contracts\JWTInterface;
use HyperfExt\Jwt\JwtManager;

// 通过 DI 注入 JwtManager 或 JWTInterface
public function __construct(
    protected JwtManager $manager
) {}

// 编码（返回 Token 值对象）
$token = $this->manager->encodeFromClaims(['user_id' => 123, 'role' => 'admin']);
$tokenString = $token->get();  // "xxx.yyy.zzz"

// 解码（返回 Payload）
$payload = $this->manager->decode($token);
$claims = $payload->toArray();  // ['user_id' => 123, 'role' => 'admin', 'iat' => ..., ...]
```

### 基于 JWTSubject 创建令牌（tymon 风格）

```php
use HyperfExt\Jwt\Contracts\JWTSubject;
use HyperfExt\Jwt\Support\CustomClaims;

class User implements JWTSubject
{
    use CustomClaims;

    public function getJWTIdentifier(): mixed
    {
        return $this->id;
    }

    // getJWTCustomClaims() 由 trait 提供空数组默认实现
    // 也可覆盖：
    public function getJWTCustomClaims(): array
    {
        return ['role' => $this->role];
    }
}

// 从用户模型创建令牌
$token = $this->manager->fromSubject($user);
```

### 解析请求令牌 + 认证（tymon 风格链式 API）

```php
$jwt = $this->manager->scene('api');

// 从 Authorization 头解析
if ($jwt->parseToken($request->getHeaderLine('Authorization'))) {
    $payload = $jwt->getPayload();      // 获取当前令牌的 Payload
    $user = $jwt->subject();            // 通过 resolver 解析用户
}

// 设置 subject resolver
$jwt->setSubjectResolver(function ($id) {
    return User::find($id);
});

// 刷新 / 吊销当前令牌
$newToken = $jwt->refresh();
$jwt->invalidate();
```

### PayloadFactory 链式 API

```php
$factory = $this->manager->default()->getPayloadFactory();

$payload = $factory
    ->sub(123)
    ->customClaims(['role' => 'admin'])
    ->setTTL(7200)    // 秒
    ->make();

$token = $this->manager->encode($payload);
```

### 多场景

```php
$jwt = $this->manager->scene('admin');
// 每个场景独立的密钥/算法/TTL/黑名单
```

### 黑名单

```php
// 吊销令牌（加入黑名单）
$this->manager->invalidate($token);

// 检查令牌是否有效
$isValid = $this->manager->validate($token);  // bool

// 刷新令牌（旧令牌自动入黑名单）
$newToken = $this->manager->refresh($token);
```

## 中间件

### JwtAuthMiddleware — 认证

```php
// config/autoload/middlewares.php
return [
    'http' => [
        \HyperfExt\Jwt\Middleware\JwtAuthMiddleware::class,
    ],
];
```

从 `Authorization: Bearer <token>` 头或 `?token=` 查询参数提取令牌，解码后将声明存入请求属性 `jwt_claims`。失败返回 401。

### RefreshMiddleware — 自动刷新

```php
return [
    'http' => [
        \HyperfExt\Jwt\Middleware\RefreshMiddleware::class,
    ],
];
```

每次请求自动刷新令牌并在响应头 `Authorization: Bearer <new-token>` 返回新令牌。过期令牌在刷新窗口内自动续期。

## 算法支持

| 算法 | 类型 | 场景配置 `algo` |
|------|------|----------------|
| HS256 | HMAC-SHA256 | `HS256` |
| HS384 | HMAC-SHA384 | `HS384` |
| HS512 | HMAC-SHA512 | `HS512` |
| RS256 | RSA-SHA256 | `RS256` |
| RS384 | RSA-SHA384 | `RS384` |
| RS512 | RSA-SHA512 | `RS512` |
| ES256 | ECDSA-P256 | `ES256` |
| ES384 | ECDSA-P384 | `ES384` |

### 密钥生成

使用上方 [生成密钥](#生成密钥) 部分的命令即可，也可手动运行 openssl（见折叠部分）。

## API 参考

### Token（值对象）

| 方法 | 返回 | 说明 |
|------|------|------|
| `__construct(string)` | - | 从字符串创建 |
| `Token::from(Token\|string)` | `self` | 工厂方法 |
| `get()` | `string` | 获取原始字符串 |
| `segments()` | `array` | 拆分为三段 |

### Manager（核心引擎）

| 方法 | 返回 | 说明 |
|------|------|------|
| `encode(Payload)` | `Token` | 编码载荷 |
| `encodeFromClaims(array)` | `Token` | 从自定义声明编码 |
| `decode(Token\|string)` | `Payload` | 解码并校验 |
| `refresh(Token\|string\|null)` | `Token` | 刷新令牌 |
| `invalidate(Token\|string\|null)` | `bool` | 吊销令牌 |
| `validate(Token\|string)` | `bool` | 验证令牌 |
| `payload(Token\|string)` | `Payload` | 获取载荷（不校验声明） |

### JWT（extends Manager）

| 方法 | 返回 | 说明 |
|------|------|------|
| `fromSubject(JWTSubject)` | `Token` | 从用户模型创建令牌 |
| `parseToken(?string)` | `self\|false` | 从 Authorization 头解析 |
| `setToken(Token\|string)` | `self` | 设置当前令牌 |
| `getToken()` | `?Token` | 获取当前令牌 |
| `getPayload()` | `Payload` | 获取当前令牌载荷 |
| `subject()` | `?JWTSubject` | 通过 resolver 解析用户 |
| `setSubjectResolver(callable)` | `self` | 设置用户解析器 |
| `reset()` | `self` | 重置令牌状态 |

### PayloadFactory

| 方法 | 返回 | 说明 |
|------|------|------|
| `customClaims(array)` | `self` | 添加自定义声明 |
| `sub(mixed)` | `self` | 设置 sub |
| `aud(mixed)` | `self` | 设置 aud |
| `iss(string)` | `self` | 设置 iss |
| `setTTL(int)` | `self` | 覆盖 TTL（秒） |
| `make(array)` | `Payload` | 构建 Payload |
| `clearClaims()` | `self` | 清空声明 |

## 异常

| 异常 | 说明 |
|------|------|
| `JWTException` | 基类 |
| `TokenInvalidException` | 令牌格式错误 / 签名不匹配 |
| `TokenExpiredException` | 令牌已过期 |
| `TokenNotYetValidException` | 令牌尚未生效 |
| `SignatureInvalidException` | 签名验证失败 |
| `TokenBlacklistedException` | 令牌已被吊销 |

## 目录结构

```
src/
├── Manager.php                    核心引擎
├── JWT.php                        JWT（extends Manager，auth 层）
├── JwtFactory.php                 从配置构建实例
├── JwtManager.php                 多场景管理器
├── PayloadFactory.php             载荷工厂（链式 API）
├── Token.php                      Token 值对象
├── ConfigProvider.php             Hyperf 配置提供者
├── Contracts/
│   ├── JWTInterface.php           JWT 服务契约
│   ├── JWTProvider.php            编解码引擎契约
│   ├── JWTSubject.php             用户模型契约
│   ├── ClaimInterface.php
│   ├── SignerInterface.php
│   └── StorageInterface.php
├── Providers/
│   └── NativeJwtProvider.php      原生 PHP 编解码实现
├── Claims/                        声明系统（11 文件）
├── Signers/                       签名器（13 文件）
├── Payload/                       Payload + Validator
├── Blacklist/                     黑名单 + 存储
├── Validators/
│   └── TokenValidator.php         令牌格式校验
├── Support/                       Base64Url / Json / CustomClaims
├── Command/
│   ├── JwtSecretCommand.php       jwt:secret — 生成 HMAC 密钥
│   └── JwtKeysCommand.php         jwt:keys — 生成 RSA/ECDSA 密钥对
├── Middleware/                    JwtAuthMiddleware + RefreshMiddleware
└── Exceptions/                    6 个异常类
```

## License

MIT
