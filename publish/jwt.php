<?php

declare(strict_types=1);

/**
 * Configuration for HyperfExt/Jwt.
 *
 * Architecture follows tymon/jwt-auth:
 *   Manager (core engine)
 *     ├── JWTProvider   (encode / decode + signing)
 *     ├── PayloadFactory (default + custom claims)
 *     ├── PayloadValidator
 *     └── Blacklist      (jti revocation via PSR-16 cache)
 *
 * Copy this file to `config/autoload/jwt.php` of your Hyperf application.
 */
return [
    /*
    |--------------------------------------------------------------------------
    | Default Scene
    |--------------------------------------------------------------------------
    |
    | The default scene used when no scene is specified.
    |
    */
    'default' => env('JWT_DEFAULT_SCENE', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Scenes
    |--------------------------------------------------------------------------
    |
    | Each scene is an independent JWT context with its own secret/keys,
    | algorithm, ttl and blacklist settings. You may define as many scenes
    | as you need (e.g. `api`, `admin`, `app`).
    |
    */
    'scenes' => [
        'default' => [
            // Secret used for HMAC algorithms (HS256/HS384/HS512).
            'secret' => env('JWT_SECRET', ''),

            // Asymmetric keys used for RSA / ECDSA algorithms (RS*, ES*).
            'keys' => [
                'public' => env('JWT_PUBLIC_KEY', ''),
                'private' => env('JWT_PRIVATE_KEY', ''),
                'passphrase' => env('JWT_PASSPHRASE', ''),
            ],

            // Signing algorithm. One of:
            // HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384
            'algo' => env('JWT_ALGO', 'HS256'),

            // Token time-to-live: minutes until expiration.
            // (tymon-style; internally converted to seconds.)
            'ttl' => (int) env('JWT_TTL', 60),

            // Refresh window: minutes from iat within which a token can be
            // refreshed. After this window the token must be re-authenticated.
            'refresh_ttl' => (int) env('JWT_REFRESH_TTL', 20160),

            // Leeway in seconds for time-based claims (clock skew tolerance).
            'leeway' => env('JWT_LEEWAY', 0),

            // Default registered claims (optional; ttl controls exp).
            'claims' => [
                'iss' => env('JWT_ISS', null),        // issuer
                'aud' => env('JWT_AUD', null),        // audience
                'nbf' => (int) env('JWT_NBF', 0),     // not before (seconds delay)
                'jti' => env('JWT_JTI', true),        // generate unique token id
            ],

            // Blacklist (token revocation) settings.
            'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

            // Grace period in seconds: a invalidated token remains valid
            // for this window (useful for token rotation).
            'blacklist_grace_period' => (int) env('JWT_BLACKLIST_GRACE', 0),

            // Maximum TTL in minutes for blacklist entries in storage.
            'blacklist_storage_ttl' => (int) env('JWT_BLACKLIST_TTL', 20160),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Blacklist Storage
    |--------------------------------------------------------------------------
    |
    | The cache driver (by name, as defined in `config/autoload/cache.php`)
    | used to persist revoked tokens. The `prefix` namespaces blacklist keys
    | so they do not collide with other cache entries.
    |
    | For production use a shared, persistent driver such as `redis` or
    | `coroutine-redis` so the blacklist is consistent across workers.
    |
    */
    'blacklist_storage' => [
        'driver' => env('JWT_BLACKLIST_DRIVER', 'default'),
        'prefix' => env('JWT_BLACKLIST_PREFIX', 'jwt:blacklist:'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Providers (swappable implementations)
    |--------------------------------------------------------------------------
    |
    | Following tymon/jwt-auth's `providers` config, you may override the
    | default class implementations. All classes must implement their
    | respective contracts.
    |
    */
    'providers' => [
        'jwt' => \HyperfExt\Jwt\Providers\NativeJwtProvider::class,
    ],
];
