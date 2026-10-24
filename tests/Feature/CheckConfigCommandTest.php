<?php

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class CheckConfigCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.key' => 'base64:'.base64_encode(random_bytes(32)),
            'app.cipher' => 'AES-256-CBC',
            'database.connections.wrapbiz.url' => null,
            'database.connections.wrapbiz.host' => '127.0.0.1',
            'database.connections.wrapbiz.sslmode' => 'disable',
        ]);
    }

    public function test_complete_configuration_passes(): void
    {
        $this->artisan('wrapbiz:check-config')
            ->expectsOutput('KBIZ_*, WRAPBIZ_*, TRUSTED_PROXIES and APP_KEY configuration is complete.')
            ->assertExitCode(0);
    }

    public function test_every_problem_is_reported_by_name_without_values(): void
    {
        config([
            'kbiz.timeout_seconds' => '20s',
            'wrapbiz.trusted_proxies' => '*',
            'app.key' => '',
            'database.connections.wrapbiz.host' => 'db.SECRET-HOST.example',
            'database.connections.wrapbiz.sslmode' => 'prefer',
        ]);

        $this->artisan('wrapbiz:check-config')
            ->expectsOutputToContain('KBIZ_TIMEOUT_SECONDS must be a whole number')
            ->expectsOutputToContain('TRUSTED_PROXIES entries must be explicit')
            ->expectsOutputToContain('APP_KEY is not set')
            ->expectsOutputToContain('WRAPBIZ_DB_SSLMODE must be verify-full (lowercase) for a non-local database')
            ->doesntExpectOutputToContain('SECRET-HOST')
            ->assertExitCode(1);
    }

    public function test_a_reused_hmac_key_is_named_without_its_value(): void
    {
        config(['wrapbiz.ip_hash_key' => config('wrapbiz.fingerprint_key')]);

        $this->artisan('wrapbiz:check-config')
            ->expectsOutputToContain('WRAPBIZ_IP_HASH_KEY must be a separately generated key')
            ->doesntExpectOutputToContain((string) config('wrapbiz.fingerprint_key'))
            ->assertExitCode(1);
    }

    public function test_the_bank_timeout_is_capped_at_45_seconds(): void
    {
        config(['kbiz.timeout_seconds' => '46']);
        $this->artisan('wrapbiz:check-config')
            ->expectsOutputToContain('KBIZ_TIMEOUT_SECONDS must be a whole number of seconds between 1 and 45.')
            ->assertExitCode(1);

        config(['kbiz.timeout_seconds' => '45']);
        $this->artisan('wrapbiz:check-config')->assertExitCode(0);
    }

    public function test_app_key_must_fit_the_cipher(): void
    {
        config(['app.key' => 'base64:'.base64_encode('too-short')]);

        $this->artisan('wrapbiz:check-config')->expectsOutputToContain('APP_KEY is not a valid key for AES-256-CBC')->assertExitCode(1);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function databaseTls(): iterable
    {
        yield 'localhost without tls' => [['host' => 'localhost', 'sslmode' => 'disable'], 0];
        yield 'ipv6 loopback without tls' => [['host' => '::1', 'sslmode' => 'disable'], 0];
        yield 'unix socket without tls' => [['host' => '/var/run/postgresql', 'sslmode' => 'disable'], 0];
        // SEC-R8-01: a non-local server must be verified.
        yield 'remote with require' => [['host' => 'db.example.com', 'sslmode' => 'require'], 1];
        yield 'remote with verify-ca' => [['host' => 'db.example.com', 'sslmode' => 'verify-ca'], 1];
        yield 'remote with verify-full' => [['host' => 'db.example.com', 'sslmode' => 'verify-full'], 0];
        yield 'localhost with require' => [['host' => 'localhost', 'sslmode' => 'require'], 0];
        yield 'localhost with verify-ca' => [['host' => '127.0.0.1', 'sslmode' => 'verify-ca'], 0];
        yield 'remote host list with one require' => [['host' => 'localhost,db.example.com', 'sslmode' => 'require'], 1];
        yield 'remote via url with require' => [['url' => 'pgsql://u:p@db.example.com:5432/wrapbiz?sslmode=require', 'host' => '127.0.0.1', 'sslmode' => 'verify-full'], 1];
        yield 'remote with prefer' => [['host' => 'db.example.com', 'sslmode' => 'prefer'], 1];
        yield 'remote with disable' => [['host' => 'db.example.com', 'sslmode' => 'disable'], 1];
        yield 'remote via url without tls' => [['url' => 'pgsql://u:p@db.example.com:5432/wrapbiz?sslmode=disable', 'host' => '127.0.0.1', 'sslmode' => 'require'], 1];
        yield 'remote via url with tls' => [['url' => 'pgsql://u:p@db.example.com:5432/wrapbiz?sslmode=verify-full', 'host' => '127.0.0.1', 'sslmode' => 'disable'], 0];
        // BUG-R2-04: exact lowercase libpq values; disable only for a non-empty, all-local host list.
        yield 'uppercase REQUIRE' => [['host' => 'localhost', 'sslmode' => 'REQUIRE'], 1];
        yield 'uppercase VERIFY-FULL' => [['host' => 'db.example.com', 'sslmode' => 'VERIFY-FULL'], 1];
        yield 'mixed case Disable on localhost' => [['host' => 'localhost', 'sslmode' => 'Disable'], 1];
        yield 'padded require' => [['host' => 'localhost', 'sslmode' => ' require'], 1];
        yield 'padded verify-full' => [['host' => 'db.example.com', 'sslmode' => 'verify-full '], 1];
        yield 'unset sslmode (libpq prefer)' => [['host' => 'db.example.com', 'sslmode' => null], 1];
        yield 'empty sslmode on localhost' => [['host' => 'localhost', 'sslmode' => ''], 1];
        yield 'prefer on localhost' => [['host' => 'localhost', 'sslmode' => 'prefer'], 1];
        yield 'allow on localhost' => [['host' => 'localhost', 'sslmode' => 'allow'], 1];
        yield 'empty host falls back to PGHOST' => [['host' => '', 'sslmode' => 'disable'], 1];
        yield 'null host' => [['host' => null, 'sslmode' => 'disable'], 1];
        yield 'host list with a remote host' => [['host' => 'localhost,db.example.com', 'sslmode' => 'disable'], 1];
        yield 'host list with an empty entry' => [['host' => 'localhost,', 'sslmode' => 'disable'], 1];
        yield 'all-local host list' => [['host' => 'localhost,127.0.0.1', 'sslmode' => 'disable'], 0];
        yield 'uppercase LOCALHOST' => [['host' => 'LOCALHOST', 'sslmode' => 'disable'], 0];
        yield 'trailing-dot localhost' => [['host' => 'localhost.', 'sslmode' => 'disable'], 1];
        yield 'url host override to remote' => [['url' => 'pgsql://u:p@localhost:5432/w?sslmode=disable&host=db.example.com', 'sslmode' => 'require'], 1];
        yield 'remote with tls, host list' => [['host' => 'db1.example.com,db2.example.com', 'sslmode' => 'verify-full'], 0];
        // SEC-R2-05: Laravel pastes these into the PDO DSN unescaped.
        yield 'host injects a second host' => [['host' => '/tmp;host=db.example.com', 'sslmode' => 'disable'], 1];
        yield 'host injects with tls' => [['host' => 'db.example.com;sslmode=disable', 'sslmode' => 'require'], 1];
        yield 'database injects via quote' => [['host' => 'localhost', 'database' => "wrapbiz' host='db.example.com", 'sslmode' => 'disable'], 1];
        yield 'database with a space' => [['host' => 'localhost', 'database' => 'wrap biz', 'sslmode' => 'disable'], 1];
        yield 'database with a backslash' => [['host' => 'localhost', 'database' => 'wrap\\biz', 'sslmode' => 'disable'], 1];
        yield 'username with an equals sign' => [['host' => 'localhost', 'username' => 'u=x', 'sslmode' => 'disable'], 1];
        yield 'username with a double quote' => [['host' => 'localhost', 'username' => 'u"', 'sslmode' => 'disable'], 1];
        yield 'host with a tab' => [['host' => "localhost\t", 'sslmode' => 'disable'], 1];
        yield 'port injects a host' => [['host' => 'localhost', 'port' => '5432;host=db.example.com', 'sslmode' => 'disable'], 1];
        yield 'port with letters' => [['host' => 'localhost', 'port' => '54x2', 'sslmode' => 'disable'], 1];
        yield 'empty port' => [['host' => 'localhost', 'port' => '', 'sslmode' => 'disable'], 1];
        yield 'integer port' => [['host' => 'localhost', 'port' => 5433, 'sslmode' => 'disable'], 0];
        // Info-2: ports are 1-65535; connection options are never accepted.
        yield 'port 0' => [['host' => 'localhost', 'port' => '0', 'sslmode' => 'disable'], 1];
        yield 'integer port 0' => [['host' => 'localhost', 'port' => 0, 'sslmode' => 'disable'], 1];
        yield 'port 65536' => [['host' => 'localhost', 'port' => '65536', 'sslmode' => 'disable'], 1];
        yield 'port 99999' => [['host' => 'localhost', 'port' => '99999', 'sslmode' => 'disable'], 1];
        yield 'integer port 70000' => [['host' => 'localhost', 'port' => 70000, 'sslmode' => 'disable'], 1];
        yield 'port 1' => [['host' => 'localhost', 'port' => '1', 'sslmode' => 'disable'], 0];
        yield 'port 65535' => [['host' => 'localhost', 'port' => '65535', 'sslmode' => 'disable'], 0];
        yield 'url port 0' => [['url' => 'pgsql://u:p@localhost:0/w?sslmode=disable'], 1];
        yield 'url query connect_via_port 70000' => [['url' => 'pgsql://u:p@localhost:5432/w?sslmode=disable&connect_via_port=70000'], 1];
        yield 'url query server_options' => [['url' => 'pgsql://u:p@db.example.com:5432/w?sslmode=require&server_options[search_path]=evil'], 1];
        yield 'url query options' => [['url' => 'pgsql://u:p@db.example.com:5432/w?sslmode=require&options=-c%20search_path%3Devil'], 1];
        yield 'server_options in config' => [['host' => 'db.example.com', 'sslmode' => 'require', 'server_options' => ['search_path' => 'evil']], 1];
        yield 'pdo options in config' => [['host' => 'db.example.com', 'sslmode' => 'require', 'options' => [1 => 1]], 1];
        yield 'url query injects connect_via_database' => [['url' => "pgsql://u:p@localhost:5432/w?sslmode=disable&connect_via_database=x'%20host='db.example.com"], 1];
        yield 'url query injects connect_via_port' => [['url' => 'pgsql://u:p@localhost:5432/w?sslmode=disable&connect_via_port=1;host=db.example.com'], 1];
        yield 'url query injects sslrootcert' => [['url' => 'pgsql://u:p@db.example.com:5432/w?sslmode=require&sslrootcert=/x;sslmode=disable'], 1];
        yield 'url query injects keepalives' => [['url' => 'pgsql://u:p@localhost:5432/w?sslmode=disable&keepalives=1;host=db.example.com'], 1];
        yield 'url encoded semicolon in host' => [['url' => 'pgsql://u:p@%2Ftmp%3Bhost%3Ddb.example.com:5432/w?sslmode=disable'], 1];
        yield 'url encoded quote in database' => [['url' => 'pgsql://u:p@localhost:5432/w%27x?sslmode=disable'], 1];
        yield 'plain url on localhost' => [['url' => 'pgsql://wrapbiz_register:p%3B%27@localhost:5432/wrapbiz?sslmode=disable'], 0];
    }

    /**
     * @param  array<string, mixed>  $connection
     */
    #[DataProvider('databaseTls')]
    public function test_remote_wrapbiz_database_requires_tls(array $connection, int $exitCode): void
    {
        foreach ($connection as $key => $value) {
            config(["database.connections.wrapbiz.{$key}" => $value]);
        }

        $this->artisan('wrapbiz:check-config')->assertExitCode($exitCode);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function redirectingPgVariables(): iterable
    {
        foreach (['PGHOSTADDR' => '203.0.113.5', 'PGSERVICE' => 'remote', 'PGSERVICEFILE' => '/tmp/pg_service.conf'] as $variable => $value) {
            yield $variable => [$variable, $value];
        }
    }

    /** BUG-R3-04: libpq would follow these to a remote server despite a local DSN. */
    #[DataProvider('redirectingPgVariables')]
    public function test_disable_is_refused_while_libpq_can_be_redirected(string $variable, string $value): void
    {
        config(['database.connections.wrapbiz.host' => 'localhost', 'database.connections.wrapbiz.sslmode' => 'disable']);
        $this->assertFalse(getenv($variable, true), "{$variable} must not be set in the test environment");

        putenv("{$variable}={$value}");
        try {
            $this->artisan('wrapbiz:check-config')
                ->expectsOutputToContain("WRAPBIZ_DB_SSLMODE=disable is not allowed while {$variable} is set in the environment")
                ->doesntExpectOutputToContain($value)
                ->assertExitCode(1);

            config(['database.connections.wrapbiz.sslmode' => 'require']);
            $this->artisan('wrapbiz:check-config')
                ->expectsOutputToContain("WRAPBIZ_DB_SSLMODE=require is not allowed while {$variable} is set in the environment")
                ->assertExitCode(1);

            config(['database.connections.wrapbiz.host' => 'db.example.com', 'database.connections.wrapbiz.sslmode' => 'verify-full']);
            $this->artisan('wrapbiz:check-config')->assertExitCode(0);
        } finally {
            putenv($variable);
        }

        config(['database.connections.wrapbiz.host' => 'localhost', 'database.connections.wrapbiz.sslmode' => 'disable']);
        $this->artisan('wrapbiz:check-config')->assertExitCode(0);
    }

    public function test_an_empty_pg_variable_does_not_redirect(): void
    {
        config(['database.connections.wrapbiz.host' => 'localhost', 'database.connections.wrapbiz.sslmode' => 'disable']);
        putenv('PGSERVICE=');
        try {
            $this->artisan('wrapbiz:check-config')->assertExitCode(0);
        } finally {
            putenv('PGSERVICE');
        }
    }

    public function test_default_sslmode_is_verify_full_when_the_variable_is_unset(): void
    {
        $this->assertStringContainsString(
            "'sslmode' => env('WRAPBIZ_DB_SSLMODE', 'verify-full')",
            (string) file_get_contents(base_path('config/database.php')),
        );
    }
}
