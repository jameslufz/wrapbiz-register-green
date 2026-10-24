<?php

namespace App\Wrapbiz;

use App\Kbiz\KbizConfigException;
use Illuminate\Support\ConfigurationUrlParser;

/**
 * Credentials and register-code hashes travel over the wrapbiz database
 * connection, so a non-local server must be verified (verify-full: the
 * certificate chain and the host name), or anyone on the path could stand in
 * for it. Mirrors the worker's rule: sslmode is an exact, lowercase libpq
 * value, and anything weaker than verify-full needs a non-empty host list
 * that is entirely local (an empty host falls back to PGHOST, which could
 * point anywhere) and no libpq variable that could redirect it.
 *
 * Laravel pastes connection values into the PDO DSN unescaped, so a value
 * that could start another DSN keyword (host=/tmp;host=remote) is refused
 * whatever the sslmode.
 */
final class DatabaseTlsPolicy
{
    private const string VERIFIED_SSL_MODE = 'verify-full';

    /** Allowed only when every host is local. */
    private const array LOCAL_ONLY_SSL_MODES = ['require', 'verify-ca', 'disable'];

    private const array LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];

    /** Values PostgresConnector::getDsn() interpolates raw, keyed by the variable named in errors. */
    private const array DSN_TEXT = [
        'host' => 'WRAPBIZ_DB_HOST',
        'database' => 'WRAPBIZ_DB_DATABASE',
        'connect_via_database' => 'WRAPBIZ_DB_URL (connect_via_database)',
        'username' => 'WRAPBIZ_DB_USERNAME',
        'sslmode' => 'WRAPBIZ_DB_SSLMODE',
        'charset' => 'WRAPBIZ_DB_URL (charset)',
        'application_name' => 'WRAPBIZ_DB_URL (application_name)',
        'sslcert' => 'WRAPBIZ_DB_URL (sslcert)',
        'sslkey' => 'WRAPBIZ_DB_URL (sslkey)',
        'sslrootcert' => 'WRAPBIZ_DB_URL (sslrootcert)',
    ];

    private const array DSN_PORTS = [
        'port' => 'WRAPBIZ_DB_PORT',
        'connect_via_port' => 'WRAPBIZ_DB_URL (connect_via_port)',
    ];

    private const array DSN_NUMBERS = [
        'keepalives' => 'WRAPBIZ_DB_URL (keepalives)',
        'keepalives_idle' => 'WRAPBIZ_DB_URL (keepalives_idle)',
        'keepalives_interval' => 'WRAPBIZ_DB_URL (keepalives_interval)',
        'keepalives_count' => 'WRAPBIZ_DB_URL (keepalives_count)',
    ];

    /**
     * server_options becomes libpq "options" (-c settings for the server
     * session); options are PDO attributes. Neither is needed here, and
     * either could weaken the connection.
     */
    private const array REFUSED_OPTIONS = [
        'server_options' => 'WRAPBIZ_DB_URL (server_options)',
        'options' => 'WRAPBIZ_DB_URL (options)',
    ];

    /**
     * libpq reads these from the process environment, and each can send a
     * connection whose DSN names only local hosts somewhere else.
     */
    private const array REDIRECTING_PG_VARIABLES = ['PGHOSTADDR', 'PGSERVICE', 'PGSERVICEFILE'];

    /**
     * @param  array<string, mixed>  $connection  the raw `database.connections.wrapbiz` config
     *
     * @throws KbizConfigException
     */
    public static function assertSafe(array $connection): void
    {
        $parsed = (new ConfigurationUrlParser)->parseConfiguration($connection);
        self::assertNoDsnInjection($parsed);

        $sslMode = $parsed['sslmode'] ?? null;
        if ($sslMode === self::VERIFIED_SSL_MODE) {
            return;
        }
        if (! in_array($sslMode, self::LOCAL_ONLY_SSL_MODES, true) || ! self::allHostsLocal($parsed['host'] ?? null)) {
            throw new KbizConfigException(
                'WRAPBIZ_DB_SSLMODE must be verify-full (lowercase) for a non-local database; '
                .'require, verify-ca and disable are only allowed when WRAPBIZ_DB_HOST is set and every host is localhost, 127.0.0.1, ::1 or a unix socket path.',
            );
        }

        $redirecting = self::setRedirectingVariable();
        if ($redirecting !== null) {
            throw new KbizConfigException(
                "WRAPBIZ_DB_SSLMODE={$sslMode} is not allowed while {$redirecting} is set in the environment (libpq could connect to a non-local server).",
            );
        }
    }

    /**
     * @param  array<string, mixed>  $parsed
     */
    private static function assertNoDsnInjection(array $parsed): void
    {
        foreach (self::REFUSED_OPTIONS as $key => $variable) {
            if (array_key_exists($key, $parsed)) {
                throw new KbizConfigException("{$variable} is not allowed.");
            }
        }

        foreach (self::DSN_PORTS as $key => $variable) {
            foreach (self::values($parsed[$key] ?? null) as $value) {
                $port = is_int($value) ? $value : (is_string($value) && preg_match('/^[0-9]{1,5}$/D', $value) === 1 ? (int) $value : 0);
                if ($port < 1 || $port > 65535) {
                    throw new KbizConfigException("{$variable} must be a port number from 1 to 65535.");
                }
            }
        }

        foreach (self::DSN_TEXT as $key => $variable) {
            foreach (self::values($parsed[$key] ?? null) as $value) {
                if (! (is_string($value) || is_int($value)) || preg_match('/[;\'"\\\\=\s\x00-\x1F\x7F]/', (string) $value) === 1) {
                    throw new KbizConfigException("{$variable} must not contain ; ' \" \\ = or whitespace.");
                }
            }
        }

        foreach (self::DSN_NUMBERS as $key => $variable) {
            foreach (self::values($parsed[$key] ?? null) as $value) {
                if (! (is_int($value) && $value >= 0) && ! (is_string($value) && preg_match('/^[0-9]{1,5}$/D', $value) === 1)) {
                    throw new KbizConfigException("{$variable} must contain digits only.");
                }
            }
        }
    }

    /**
     * @return list<mixed>
     */
    private static function values(mixed $value): array
    {
        return match (true) {
            $value === null => [],
            is_array($value) => array_values($value),
            default => [$value],
        };
    }

    private static function setRedirectingVariable(): ?string
    {
        foreach (self::REDIRECTING_PG_VARIABLES as $variable) {
            foreach ([getenv($variable, true), getenv($variable)] as $value) {
                if (is_string($value) && $value !== '') {
                    return $variable;
                }
            }
        }

        return null;
    }

    private static function allHostsLocal(mixed $hostConfig): bool
    {
        $hosts = is_array($hostConfig) ? $hostConfig : explode(',', is_string($hostConfig) ? $hostConfig : '');
        foreach ($hosts as $host) {
            if (! is_string($host) || ! self::isLocal($host)) {
                return false;
            }
        }

        return true;
    }

    private static function isLocal(string $host): bool
    {
        return str_starts_with($host, '/') || in_array(strtolower($host), self::LOCAL_HOSTS, true);
    }
}
