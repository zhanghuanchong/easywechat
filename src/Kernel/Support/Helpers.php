<?php

/*
 * This file is part of the overtrue/wechat.
 *
 * (c) overtrue <i@overtrue.me>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace EasyWeChat\Kernel\Support;

/*
 * helpers.
 *
 * @author overtrue <i@overtrue.me>
 */

/**
 * Generate a signature.
 *
 * @param array  $attributes
 * @param string $key
 * @param string $encryptMethod
 *
 * @return string
 */
function generate_sign(array $attributes, $key, $encryptMethod = 'md5')
{
    ksort($attributes);

    $attributes['key'] = $key;

    return strtoupper(call_user_func_array($encryptMethod, [urldecode(http_build_query($attributes))]));
}

/**
 * @param string $signType
 * @param string $secretKey
 *
 * @return \Closure|string
 */
function get_encrypt_method(string $signType, string $secretKey = '')
{
    if ('HMAC-SHA256' === $signType) {
        return function ($str) use ($secretKey) {
            return hash_hmac('sha256', $str, $secretKey);
        };
    }

    return 'md5';
}

function get_server_input()
{
    if (function_exists('request')) {
        return request()->server();
    }
    return $_SERVER ?? [];
}

/**
 * Get client ip.
 *
 * @return string
 */
function get_client_ip()
{
    $server = get_server_input();
    if (!empty($server['REMOTE_ADDR'])) {
        $ip = $server['REMOTE_ADDR'];
    } else {
        // for php-cli(phpunit etc.)
        $ip = defined('PHPUNIT_RUNNING') ? '127.0.0.1' : gethostbyname(gethostname());
    }

    return filter_var($ip, FILTER_VALIDATE_IP) ?: '127.0.0.1';
}

/**
 * Get current server ip.
 *
 * @return string
 */
function get_server_ip()
{
    $server = get_server_input();
    if (!empty($server['SERVER_ADDR'])) {
        $ip = $server['SERVER_ADDR'];
    } elseif (!empty($server['SERVER_NAME'])) {
        $ip = gethostbyname($server['SERVER_NAME']);
    } else {
        // for php-cli(phpunit etc.)
        $ip = defined('PHPUNIT_RUNNING') ? '127.0.0.1' : gethostbyname(gethostname());
    }

    return filter_var($ip, FILTER_VALIDATE_IP) ?: '127.0.0.1';
}

/**
 * Return current url.
 *
 * @return string
 */
function current_url()
{
    $server = get_server_input();
    $protocol = 'http://';

    if ((!empty($server['HTTPS']) && 'off' !== $server['HTTPS']) || ($server['HTTP_X_FORWARDED_PROTO'] ?? 'http') === 'https') {
        $protocol = 'https://';
    }

    return $protocol.$server['HTTP_HOST'].$server['REQUEST_URI'];
}

/**
 * Return random string.
 *
 * @param string $length
 *
 * @return string
 */
function str_random($length)
{
    return Str::random($length);
}

/**
 * @param string $content
 * @param string $publicKey
 *
 * @return string
 */
function rsa_public_encrypt($content, $publicKey)
{
    $encrypted = '';
    openssl_public_encrypt($content, $encrypted, openssl_pkey_get_public($publicKey), OPENSSL_PKCS1_OAEP_PADDING);

    return base64_encode($encrypted);
}
