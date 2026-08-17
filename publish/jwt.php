<?php

declare(strict_types=1);

/**
 * JWT Authentication Configuration for Hyperf
 *
 * Adapted from tymon/jwt-auth for the Hyperf framework.
 */

use Kooditorm\Hyperf\Jwt\Providers\JWT\Lcobucci;
use function Hyperf\Support\env;

return [

    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Set this in your .env file. Use `php bin/hyperf.php jwt:secret`
    | to generate a random secret.
    |
    | Used for Symmetric algorithms only (HMAC).
    | RSA and ECDSA use a private/public key combo (see below).
    |
    */

    'secret' => env('JWT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Keys
    |--------------------------------------------------------------------------
    |
    | Symmetric Algorithms (HS256, HS384, HS512) use `secret`.
    | Asymmetric Algorithms (RS256, ES256, etc.) use the keys below.
    |
    */

    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
        'passphrase' => env('JWT_PASSPHRASE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT time to live (in minutes)
    |--------------------------------------------------------------------------
    |
    | The token validity duration. Default: 60 minutes (1 hour).
    | Set to null for a never-expiring token (not recommended).
    | If null, remove 'exp' from 'required_claims'.
    |
    */

    'ttl' => env('JWT_TTL', 60),

    /*
    |--------------------------------------------------------------------------
    | Refresh time to live (in minutes)
    |--------------------------------------------------------------------------
    |
    | The window within which a token can be refreshed.
    | Default: 20160 minutes (2 weeks).
    |
    */

    'refresh_ttl' => env('JWT_REFRESH_TTL', 20160),

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    |
    | Default: HS256
    |
    */

    'algo' => env('JWT_ALGO', Lcobucci::ALGO_HS256),

    /*
    |--------------------------------------------------------------------------
    | Issuer claim
    |--------------------------------------------------------------------------
    |
    | The issuer (iss) claim. If null, the issuer is auto-detected
    | from the request URL.
    |
    */

    'iss' => env('JWT_ISSUER'),

    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    |
    | Claims that must exist in any token.
    |
    */

    'required_claims' => [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ],

    /*
    |--------------------------------------------------------------------------
    | Persistent Claims
    |--------------------------------------------------------------------------
    |
    | Claims to persist when refreshing a token.
    | 'sub' and 'iat' are always persisted.
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
    |
    | Adds a 'prv' claim to prevent cross-model token impersonation.
    |
    */

    'lock_subject' => true,

    /*
    |--------------------------------------------------------------------------
    | Leeway (seconds)
    |--------------------------------------------------------------------------
    |
    | Time cushion for clock skew. Applies to iat, nbf, and exp claims.
    |
    */

    'leeway' => env('JWT_LEEWAY', 0),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Enabled
    |--------------------------------------------------------------------------
    |
    | Required for token invalidation.
    |
    */

    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Grace Period (seconds)
    |--------------------------------------------------------------------------
    |
    | Prevents parallel request failures during token regeneration.
    |
    */

    'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 0),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The model used for authentication.
    |
    */

    'user_model' => env('JWT_USER_MODEL', 'App\Model\User'),

    /*
   |--------------------------------------------------------------------------
   | Authentication Guards & Providers
   |--------------------------------------------------------------------------
   |
   | Modeled after Laravel's auth config. Define multiple guards
   | (scenarios) each backed by a user provider (model).
   |
   | Example scenarios: api (App users), admin (backend admins).
   |
   | Each guard maps to one provider. Each provider maps to one model class.
   | The default guard is used when none is explicitly specified.
   |
   */
    'auth' => [
        /*
        | Default guard to use.
        */
        'defaults' => env('JWT_GUARD_DEFAULT', 'api'),

        /*
        | Guard configurations.
        | Each guard specifies its driver ('jwt') and the user provider.
        */
        'guards' => [
            'api' => [
                'provider' => 'users',
            ],

            'admin' => [
                'provider' => 'admins',
            ],
        ],

        /*
        | User Provider configurations.
        | Each provider maps a guard to a specific user model.
        */
        'providers' => [
            'users' => [
                'model' => App\Model\Admin,
            ]
        ],
    ],


    /*
    |--------------------------------------------------------------------------
    | Providers
    |--------------------------------------------------------------------------
    |
    | Override the default provider classes if needed.
    |
    */

    'providers' => [
        'jwt' => Lcobucci::class,
        'auth' => \Kooditorm\Hyperf\Jwt\Providers\Auth\HyperfAuth::class,
        'storage' => \Kooditorm\Hyperf\Jwt\Providers\Storage\HyperfCache::class,
    ],

];
