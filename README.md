# Kooditorm Hyperf JWT

基于 [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth) 适配 Hyperf 框架的 JSON Web Token 认证包。

## 特性

- 完整的 JWT 编码/解码/刷新/黑名单机制
- 协程安全（使用 Hyperf Context 存储请求级状态）
- PSR-15 中间件
- 支持 HMAC / RSA / ECDSA 算法
- 基于 Lcobucci JWT 库
- 可插拔的 Provider 架构（JWT / Auth / Storage）
- Hyperf ConfigProvider 自动注册
- 命令行生成密钥

## 安装

```bash
composer require kooditorm/hyperf-jwt
```

发布配置文件：

```bash
php bin/hyperf.php vendor:publish kooditorm/hyperf-jwt
```

生成密钥：

```bash
php bin/hyperf.php jwt:secret
```

## 配置

配置文件位于 `config/autoload/jwt.php`：

```php
return [
    'secret' => env('JWT_SECRET'),
    'ttl' => 60,                    // token 有效期（分钟）
    'refresh_ttl' => 20160,         // 刷新窗口（分钟）
    'algo' => 'HS256',              // 签名算法
    'blacklist_enabled' => true,    // 启用黑名单
    'user_model' => 'App\Model\User',
    // ...
];
```

## 使用

### 1. User 模型实现 JWTSubject 接口

```php
namespace App\Model;

use Kooditorm\Hyperf\Jwt\Contracts\JWTSubject;
use Hyperf\Database\Model\Model;

class User extends Model implements JWTSubject
{
    public function getJWTIdentifier(): mixed
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims(): array
    {
        return [
            // 'role' => 'admin',
        ];
    }

    public function getAuthPassword(): string
    {
        return $this->password;
    }
}
```

### 2. 生成 Token

```php
use Kooditorm\Hyperf\Jwt\JWTAuth;

class AuthController
{
    public function __construct(private JWTAuth $jwt) {}

    public function login()
    {
        $credentials = [
            'email' => $request->input('email'),
            'password' => $request->input('password'),
        ];

        if (! $token = $this->jwt->attempt($credentials)) {
            return ['error' => 'Unauthorized'];
        }

        return [
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->jwt->factory()->getTTL() * 60,
        ];
    }

    // 从指定用户生成 token
    public function tokenForUser(User $user): string
    {
        return $this->jwt->fromUser($user);
    }
}
```

### 3. 中间件鉴权

在 `config/autoload/middlewares.php` 中注册：

```php
return [
    'http' => [
        // 路由级中间件
    ],
];
```

或直接在控制器注解中使用：

```php
use Kooditorm\Hyperf\Jwt\Http\Middleware\JWTAuthMiddleware;

class UserController
{
    #[Middleware(JWTAuthMiddleware::class)]
    public function profile()
    {
        $user = $this->jwt->user();
        return $user;
    }
}
```

### 4. 刷新 Token

```php
// 刷新当前 token
$newToken = $this->jwt->parseToken()->refresh();

// 或使用中间件自动刷新
use Kooditorm\Hyperf\Jwt\Http\Middleware\JWTRefreshMiddleware;

#[Middleware(JWTRefreshMiddleware::class)]
public function refresh()
{
    // 新 token 已在 Authorization 响应头中
}
```

### 5. 注销/拉黑 Token

```php
$this->jwt->parseToken()->invalidate();      // 拉黑当前 token
$this->jwt->parseToken()->invalidate(true);  // 永久拉黑
```

### 6. 使用 Facade

```php
use Kooditorm\Hyperf\Jwt\Facades\JWTAuth;

$token = JWTAuth::attempt($credentials);
$user = JWTAuth::user();
$payload = JWTAuth::payload();
```

## 中间件列表

| 中间件 | 说明 |
|--------|------|
| `JWTAuthMiddleware` | 验证 token 并认证用户，失败返回 401 |
| `JWTCheckMiddleware` | 检查 token 有效性，不强制要求 |
| `JWTRefreshMiddleware` | 刷新 token，新 token 放入响应头 |
| `JWTAuthAndRenewMiddleware` | 认证 + 刷新 token |

## 自定义 Provider

### 自定义 Auth Provider

```php
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth;

class MyAuthProvider implements Auth
{
    public function byCredentials(array $credentials): bool { ... }
    public function byId(mixed $id): bool { ... }
    public function user(): mixed { ... }
}
```

在 ConfigProvider 中绑定：

```php
// config/autoload/dependencies.php
return [
    \Kooditorm\Hyperf\Jwt\Contracts\Providers\Auth::class => \App\Provider\MyAuthProvider::class,
];
```

### 自定义 Storage Provider（如 Redis）

```php
use Kooditorm\Hyperf\Jwt\Contracts\Providers\Storage;
use Hyperf\Redis\Redis;

class RedisStorage implements Storage
{
    public function __construct(private Redis $redis) {}

    public function add(string $key, mixed $value, int $minutes): void
    {
        $this->redis->setex($key, $minutes * 60, serialize($value));
    }

    public function forever(string $key, mixed $value): void
    {
        $this->redis->set($key, serialize($value));
    }

    public function get(string $key): mixed
    {
        $val = $this->redis->get($key);
        return $val !== false ? unserialize($val) : null;
    }

    public function destroy(string $key): bool
    {
        return (bool) $this->redis->del($key);
    }

    public function flush(): void
    {
        $this->redis->flushDB();
    }
}
```

## 协程安全

本包使用 `Hyperf\Context\Context` 存储当前请求的 token 和认证用户，确保在 Swoole 协程环境下安全使用。每个协程拥有独立的 token 上下文，互不干扰。

## 致谢

- [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth) - 原始 JWT 包
- [lcobucci/jwt](https://github.com/lcobucci/jwt) - JWT 编解码库
- [Hyperf](https://hyperf.io/) - 高性能协程框架

## License

MIT
