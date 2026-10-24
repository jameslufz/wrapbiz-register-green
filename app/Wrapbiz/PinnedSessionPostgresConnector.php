<?php

namespace App\Wrapbiz;

use Illuminate\Database\Connectors\PostgresConnector;
use PDO;

/**
 * Every PostgreSQL session this app opens gets these settings, on each new
 * connection including reconnects:
 *  - time limits, so a stuck lock or a slow function fails the request
 *    instead of holding a PHP worker and its database connection;
 *  - READ COMMITTED, which register_connection() requires of its callers
 *    (a role or database default could otherwise change it).
 * Deliberately not configurable: a value in the connection config could be
 * overridden by a WRAPBIZ_DB_URL query parameter.
 */
final class PinnedSessionPostgresConnector extends PostgresConnector
{
    public const string STATEMENT_TIMEOUT = '15s';

    public const string LOCK_TIMEOUT = '5s';

    public const string ISOLATION_LEVEL = 'read committed';

    /**
     * @param  array<string, mixed>  $config
     */
    public function connect(array $config): PDO
    {
        return self::pin(parent::connect($config));
    }

    public static function pin(PDO $connection): PDO
    {
        $connection->exec(sprintf(
            "select set_config('statement_timeout', '%s', false), set_config('lock_timeout', '%s', false),"
            ." set_config('default_transaction_isolation', '%s', false)",
            self::STATEMENT_TIMEOUT,
            self::LOCK_TIMEOUT,
            self::ISOLATION_LEVEL,
        ));

        return $connection;
    }
}
