<?php

namespace Tests\Feature;

use App\Kbiz\KbizConfigException;
use App\Wrapbiz\PinnedSessionPostgresConnector;
use App\Wrapbiz\RegistrationStore;
use Illuminate\Database\Connectors\ConnectionFactory;
use Mockery;
use PDO;
use Tests\TestCase;

final class PinnedSessionPostgresConnectorTest extends TestCase
{
    public function test_every_postgres_connection_including_wrapbiz_uses_the_pinned_connector(): void
    {
        $factory = $this->app->make(ConnectionFactory::class);

        $this->assertInstanceOf(PinnedSessionPostgresConnector::class, $factory->createConnector((array) config('database.connections.wrapbiz')));
        $this->assertInstanceOf(PinnedSessionPostgresConnector::class, $factory->createConnector(['driver' => 'pgsql']));
    }

    public function test_the_session_settings_are_fixed_values(): void
    {
        $this->assertSame('15s', PinnedSessionPostgresConnector::STATEMENT_TIMEOUT);
        $this->assertSame('5s', PinnedSessionPostgresConnector::LOCK_TIMEOUT);
        $this->assertSame('read committed', PinnedSessionPostgresConnector::ISOLATION_LEVEL);
    }

    public function test_settings_are_made_for_the_whole_session_in_one_round_trip(): void
    {
        $pdo = Mockery::mock(PDO::class);
        $pdo->shouldReceive('exec')->once()
            ->with("select set_config('statement_timeout', '15s', false), set_config('lock_timeout', '5s', false),"
                ." set_config('default_transaction_isolation', 'read committed', false)")
            ->andReturn(0);

        $this->assertSame($pdo, PinnedSessionPostgresConnector::pin($pdo));
    }

    public function test_a_failure_to_set_them_fails_the_connection(): void
    {
        $pdo = Mockery::mock(PDO::class);
        $pdo->shouldReceive('exec')->once()->andThrow(new \PDOException('SQLSTATE[08006]: connection lost'));

        $this->expectException(\PDOException::class);
        PinnedSessionPostgresConnector::pin($pdo);
    }

    /** D3: console and queue code reach the store without the web boot check. */
    public function test_the_store_binding_refuses_an_unverified_remote_database(): void
    {
        config(['database.connections.wrapbiz.host' => 'db.example.com', 'database.connections.wrapbiz.sslmode' => 'require']);

        try {
            $this->app->make(RegistrationStore::class);
            $this->fail('expected the TLS policy to refuse');
        } catch (KbizConfigException $exception) {
            $this->assertStringContainsString('WRAPBIZ_DB_SSLMODE must be verify-full', $exception->getMessage());
            $this->assertStringNotContainsString('db.example.com', $exception->getMessage());
        }

        config(['database.connections.wrapbiz.sslmode' => 'verify-full']);
        $this->assertInstanceOf(RegistrationStore::class, $this->app->make(RegistrationStore::class));
    }
}
