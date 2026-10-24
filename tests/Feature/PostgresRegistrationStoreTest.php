<?php

namespace Tests\Feature;

use App\Wrapbiz\AccountState;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\NewAccount;
use App\Wrapbiz\NewRegistration;
use App\Wrapbiz\PostgresRegistrationStore;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStoreUnavailable;
use App\Wrapbiz\RejectionReason;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;
use Mockery;
use PDOException;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class PostgresRegistrationStoreTest extends TestCase
{
    /** The pinned hand-over columns of a register_connection row that is not a hand-over. */
    private const array NO_HANDOVER = ['gap_from' => null, 'gap_to' => null, 'handover' => false, 'gap_delivered_count' => null, 'gap_pending_count' => null];

    private function registration(): NewRegistration
    {
        return new NewRegistration(
            codeHash: str_repeat("\x01", 32),
            provider: 'kbank',
            webhookUrl: 'https://hooks.example.com/x',
            connectionId: '01900000-0000-7000-8000-000000000001',
            sealedCredential: "\x00\xffsealed",
            orgFingerprint: str_repeat("\x03", 32),
            userFingerprint: str_repeat("\x04", 32),
            accounts: [new NewAccount('01900000-0000-7000-8000-000000000002', str_repeat("\xab", 32), 'xxx-x-x1234-x', "\x10\x20")],
            ipHash: str_repeat("\x02", 32),
        );
    }

    private static function queryException(string $sqlState, string $driverMessage): QueryException
    {
        $pdo = new PDOException("SQLSTATE[{$sqlState}]: {$driverMessage}");
        $pdo->errorInfo = [$sqlState, 7, $driverMessage];

        return new QueryException('wrapbiz', 'select * from register_connection(?, ?)', ['SECRET-BINDING'], $pdo);
    }

    public function test_binds_binary_values_as_text_by_parameter_name_and_maps_rows(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->withArgs(function (string $sql, array $bindings) {
            $this->assertSame(
                "register_connection( p_code_hash => decode(?, 'hex'), p_provider => ?, p_webhook_url => ?, p_connection_id => ?::uuid,"
                ." p_sealed_cred => decode(?, 'base64'), p_org_fingerprint => decode(?, 'hex'), p_user_fingerprint => decode(?, 'hex'),"
                ." p_accounts => ?::jsonb, p_ip_hash => decode(?, 'hex'))",
                substr((string) preg_replace('/\s+/', ' ', $sql), (int) strpos((string) preg_replace('/\s+/', ' ', $sql), 'register_connection(')),
            );
            $this->assertStringContainsString('account_id::text as account_id, reattached', $sql);
            $this->assertStringContainsString("to_char(last_success_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as last_success_at", $sql);
            $this->assertStringContainsString("to_char(registered_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as registered_at", $sql);
            $this->assertCount(9, $bindings);
            $this->assertSame(str_repeat('01', 32), $bindings[0]);
            $this->assertSame('kbank', $bindings[1]);
            $this->assertSame('https://hooks.example.com/x', $bindings[2]);
            $this->assertSame('01900000-0000-7000-8000-000000000001', $bindings[3]);
            $this->assertSame(base64_encode("\x00\xffsealed"), $bindings[4]);
            $this->assertSame(str_repeat('03', 32), $bindings[5], 'organisation fingerprint');
            $this->assertSame(str_repeat('04', 32), $bindings[6], 'user fingerprint');
            $this->assertSame([[
                'id' => '01900000-0000-7000-8000-000000000002',
                'fingerprint' => str_repeat('ab', 32),
                'masked' => 'xxx-x-x1234-x',
                'sealed' => base64_encode("\x10\x20"),
            ]], json_decode($bindings[7], true));
            $this->assertSame(str_repeat('02', 32), $bindings[8]);

            return true;
        })->andReturn([
            (object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => '2026-10-01T03:04:05Z', 'registered_at' => '2026-09-01T01:02:03Z', ...self::NO_HANDOVER],
            (object) ['account_id' => 'acc-2', 'reattached' => true, 'last_success_at' => null, 'registered_at' => '2026-08-01T00:00:00Z', ...self::NO_HANDOVER],
            (object) ['account_id' => 'acc-3', 'reattached' => false, 'last_success_at' => null, 'registered_at' => '2026-10-16T00:00:00Z', ...self::NO_HANDOVER],
        ]);

        $result = (new PostgresRegistrationStore($db))->register($this->registration());

        $this->assertSame(['acc-1', 'acc-2', 'acc-3'], array_map(fn ($row) => $row->id, $result));
        $this->assertSame([true, true, false], array_map(fn ($row) => $row->reattached, $result));
        $this->assertSame('2026-10-01T03:04:05+00:00', $result[0]->lastSuccessAt?->format(DATE_ATOM));
        $this->assertNull($result[1]->lastSuccessAt);
        $this->assertNull($result[2]->lastSuccessAt);
        $this->assertSame('2026-09-01T01:02:03+00:00', $result[0]->registeredAt?->format(DATE_ATOM));
        $this->assertSame('2026-10-01T03:04:05+00:00', $result[0]->pollingStart()?->format(DATE_ATOM), 'the watermark wins');
        $this->assertSame('2026-08-01T00:00:00+00:00', $result[1]->pollingStart()?->format(DATE_ATOM), 'never polled: registration time');
        $this->assertNull($result[2]->registeredAt, 'a new account has no earlier registration');
        $this->assertNull($result[2]->pollingStart());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unreadableWatermarks(): iterable
    {
        yield 'empty (infinity)' => [''];
        yield 'local time format' => ['2026-10-01 03:04:05+07'];
        yield 'impossible date' => ['2026-02-30T00:00:00Z'];
        yield 'trailing data' => ['2026-10-01T03:04:05Z '];
        yield 'not a string' => [12345];
    }

    #[DataProvider('unreadableWatermarks')]
    public function test_an_unreadable_timestamp_never_turns_a_committed_registration_into_an_error(mixed $value): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message.' '.json_encode($message->context);
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([
            (object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => $value, 'registered_at' => '2026-09-01T00:00:00Z', ...self::NO_HANDOVER],
            (object) ['account_id' => 'acc-2', 'reattached' => true, 'last_success_at' => null, 'registered_at' => $value, ...self::NO_HANDOVER],
        ]);

        $result = (new PostgresRegistrationStore($db))->register($this->registration());

        $this->assertSame(['acc-1', 'acc-2'], [$result[0]->id, $result[1]->id]);
        $this->assertNull($result[0]->lastSuccessAt);
        $this->assertNull($result[1]->registeredAt);
        $this->assertNull($result[1]->pollingStart());
        $this->assertContains('register_connection returned an unreadable timestamp {"column":"last_success_at"}', $logged);
        $this->assertContains('register_connection returned an unreadable timestamp {"column":"registered_at"}', $logged);
    }

    public function test_a_missing_registered_at_column_only_hides_the_never_polled_range(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => null, ...self::NO_HANDOVER]]);

        $result = (new PostgresRegistrationStore($db))->register($this->registration());

        $this->assertNull($result[0]->pollingStart());
    }

    public function test_a_watermark_on_a_new_account_is_ignored(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) ['account_id' => 'acc-1', 'reattached' => false, 'last_success_at' => '2026-10-01T03:04:05Z', 'registered_at' => '2026-09-01T00:00:00Z', ...self::NO_HANDOVER]]);

        $row = (new PostgresRegistrationStore($db))->register($this->registration())[0];
        $this->assertNull($row->lastSuccessAt);
        $this->assertNull($row->registeredAt);
    }

    /**
     * @return iterable<string, array{array<int, object>}>
     */
    public static function malformedRows(): iterable
    {
        yield 'no rows' => [[]];
        yield 'reattached as text' => [[(object) ['account_id' => 'a', 'reattached' => 'f']]];
        yield 'missing id' => [[(object) ['reattached' => false]]];
    }

    /**
     * @param  array<int, object>  $rows
     */
    #[DataProvider('malformedRows')]
    public function test_unexpected_register_rows_are_a_contract_failure(array $rows): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn($rows);

        $this->expectException(RegistrationStoreUnavailable::class);
        (new PostgresRegistrationStore($db))->register($this->registration());
    }

    public function test_code_status_maps_every_contract_value(): void
    {
        foreach (CodeStatus::cases() as $status) {
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('selectOne')->once()
                ->with("select registration_code_usable(decode(?, 'hex')) as status", [str_repeat('01', 32)])
                ->andReturn((object) ['status' => $status->value]);

            $this->assertSame($status, (new PostgresRegistrationStore($db))->codeStatus(str_repeat("\x01", 32)));
        }
    }

    public function test_unknown_code_status_text_fails_closed(): void
    {
        foreach ([(object) ['status' => 'maybe'], (object) ['status' => true], null] as $row) {
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('selectOne')->andReturn($row);

            try {
                (new PostgresRegistrationStore($db))->codeStatus(str_repeat("\x01", 32));
                $this->fail('expected a contract failure');
            } catch (RegistrationStoreUnavailable $exception) {
                $this->assertSame('contract', $exception->sqlState);
            }
        }
    }

    private const string RESERVATION = '0199f2a4-5b6c-7d8e-9f00-0000000000c1';

    public function test_begin_login_attempt_maps_every_contract_value(): void
    {
        foreach (LoginAttempt::cases() as $attempt) {
            $reserved = $attempt === LoginAttempt::Reserved;
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('selectOne')->once()
                ->with("select status, reservation_id::text as reservation_id from registration_code_begin_attempt(decode(?, 'hex'))", [str_repeat('01', 32)])
                ->andReturn((object) ['status' => $attempt->value, 'reservation_id' => $reserved ? strtoupper(self::RESERVATION) : null]);

            $result = (new PostgresRegistrationStore($db))->beginLoginAttempt(str_repeat("\x01", 32));

            $this->assertSame($attempt, $result->attempt);
            $this->assertSame($reserved ? self::RESERVATION : null, $result->reservationId);
        }
    }

    /**
     * @return iterable<string, array{?object}>
     */
    public static function malformedBeginAnswers(): iterable
    {
        yield 'old text answer' => [(object) ['attempt' => 'ok']];
        yield 'unknown status' => [(object) ['status' => 'usable', 'reservation_id' => null]];
        yield 'uppercase status' => [(object) ['status' => 'OK', 'reservation_id' => self::RESERVATION]];
        yield 'status not text' => [(object) ['status' => true, 'reservation_id' => null]];
        yield 'ok without a reservation' => [(object) ['status' => 'ok', 'reservation_id' => null]];
        yield 'ok with a malformed reservation' => [(object) ['status' => 'ok', 'reservation_id' => 'not-a-uuid']];
        yield 'ok with a reservation and trailing data' => [(object) ['status' => 'ok', 'reservation_id' => self::RESERVATION."\n"]];
        yield 'busy with a reservation' => [(object) ['status' => 'busy', 'reservation_id' => self::RESERVATION]];
        yield 'locked with a reservation' => [(object) ['status' => 'locked', 'reservation_id' => self::RESERVATION]];
        yield 'empty row' => [(object) []];
        yield 'no row' => [null];
    }

    #[DataProvider('malformedBeginAnswers')]
    public function test_a_malformed_begin_attempt_answer_fails_closed(?object $row): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('selectOne')->andReturn($row);

        try {
            (new PostgresRegistrationStore($db))->beginLoginAttempt(str_repeat("\x01", 32));
            $this->fail('expected a contract failure');
        } catch (RegistrationStoreUnavailable $exception) {
            $this->assertSame('contract', $exception->sqlState);
        }
    }

    public function test_end_login_attempt_releases_exactly_its_reservation(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('selectOne')->once()
            ->with("select registration_code_end_attempt(decode(?, 'hex'), ?::uuid)", [str_repeat('01', 32), self::RESERVATION])
            ->andReturn((object) ['registration_code_end_attempt' => null]);
        (new PostgresRegistrationStore($db))->endLoginAttempt(str_repeat("\x01", 32), self::RESERVATION);

        $failing = Mockery::mock(ConnectionInterface::class);
        $failing->shouldReceive('selectOne')->andThrow(self::queryException('08006', 'connection lost'));
        $this->expectException(RegistrationStoreUnavailable::class);
        (new PostgresRegistrationStore($failing))->endLoginAttempt(str_repeat("\x01", 32), self::RESERVATION);
    }

    public function test_record_failed_login_passes_its_reservation_or_null(): void
    {
        foreach ([[true, self::RESERVATION], [false, self::RESERVATION], [false, null]] as [$locked, $reservation]) {
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('selectOne')->once()
                ->with("select registration_code_record_failure(decode(?, 'hex'), ?::uuid) as locked", [str_repeat('01', 32), $reservation])
                ->andReturn((object) ['locked' => $locked]);

            $this->assertSame($locked, (new PostgresRegistrationStore($db))->recordFailedLogin(str_repeat("\x01", 32), $reservation));
        }

        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('selectOne')->andReturn((object) ['locked' => 'f']);
        $this->expectException(RegistrationStoreUnavailable::class);
        (new PostgresRegistrationStore($db))->recordFailedLogin(str_repeat("\x01", 32), null);
    }

    public function test_maps_business_errors(): void
    {
        foreach (array_filter(RejectionReason::cases(), fn (RejectionReason $r) => $r !== RejectionReason::InvalidInput) as $reason) {
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('select')->andThrow(self::queryException('P0001', "ERROR:  {$reason->value}\nCONTEXT:  PL/pgSQL function"));

            try {
                (new PostgresRegistrationStore($db))->register($this->registration());
                $this->fail('expected rejection');
            } catch (RegistrationRejected $rejection) {
                $this->assertSame($reason, $rejection->reason);
                $this->assertNull($rejection->getPrevious());
            }
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sessionLimitErrors(): iterable
    {
        yield 'statement_timeout' => ['57014'];
        yield 'lock_timeout' => ['55P03'];
    }

    #[DataProvider('sessionLimitErrors')]
    public function test_a_session_time_limit_is_a_store_outage_not_a_rejection(string $sqlState): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException($sqlState, 'ERROR:  canceling statement due to timeout'));
        $db->shouldReceive('selectOne')->andThrow(self::queryException($sqlState, 'ERROR:  canceling statement due to timeout'));
        $store = new PostgresRegistrationStore($db);

        foreach ([
            fn () => $store->codeStatus(str_repeat("\x01", 32)),
            fn () => self::statesOf($db, [str_repeat("\xaa", 32)]),
            fn () => $store->register($this->registration()),
        ] as $call) {
            try {
                $call();
                $this->fail('expected an outage');
            } catch (RegistrationStoreUnavailable $exception) {
                $this->assertSame($sqlState, $exception->sqlState);
            }
        }
    }

    public function test_check_violations_are_a_validation_rejection(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException('23514', 'new row for relation "webhook_endpoints" violates check constraint'));

        try {
            (new PostgresRegistrationStore($db))->register($this->registration());
            $this->fail('expected rejection');
        } catch (RegistrationRejected $rejection) {
            $this->assertSame(RejectionReason::InvalidInput, $rejection->reason);
            $this->assertNull($rejection->getPrevious());
        }

        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException('P0001', 'ERROR:  check_violation'));
        $this->expectException(RegistrationStoreUnavailable::class);
        (new PostgresRegistrationStore($db))->register($this->registration());
    }

    public function test_other_errors_never_leak_sql_or_bindings(): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message.json_encode($message->context);
        });

        foreach ([['P0001', 'ERROR:  something_else'], ['P0001', 'ERROR:  account_already_registered_v2'], ['23505', 'duplicate key'], ['08006', 'connection refused']] as [$state, $msg]) {
            $db = Mockery::mock(ConnectionInterface::class);
            $db->shouldReceive('select')->andThrow(self::queryException($state, $msg));

            try {
                (new PostgresRegistrationStore($db))->register($this->registration());
                $this->fail('expected unavailable');
            } catch (RegistrationStoreUnavailable $exception) {
                $this->assertSame($state, $exception->sqlState);
                $this->assertNull($exception->getPrevious());
                $this->assertStringNotContainsString('register_connection', $exception->getMessage());
                $this->assertStringNotContainsString('SECRET-BINDING', $exception->getMessage());
            }
        }

        $this->assertStringNotContainsString('SECRET-BINDING', implode("\n", $logged));
        $this->assertStringNotContainsString('select', implode("\n", $logged));
    }

    /**
     * @param  list<string>  $fingerprints
     * @return array<string, AccountState>
     */
    private static function statesOf(ConnectionInterface $db, array $fingerprints): array
    {
        return (new PostgresRegistrationStore($db))->accountStates(str_repeat("\x01", 32), str_repeat("\x03", 32), str_repeat("\x04", 32), $fingerprints);
    }

    public function test_account_states_bind_by_parameter_name_and_key_the_answer_by_fingerprint(): void
    {
        $a = str_repeat("\xaa", 32);
        $b = str_repeat("\xbb", 32);
        $c = str_repeat("\xcc", 32);
        $d = str_repeat("\xdd", 32);
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->withArgs(function (string $sql, array $bindings) {
            $flat = (string) preg_replace('/\s+/', ' ', $sql);
            $this->assertStringContainsString("select encode(fingerprint, 'hex') as fingerprint, state from registration_account_states(", $flat);
            $this->assertStringContainsString(
                "p_code_hash => decode(?, 'hex'), p_org_fingerprint => decode(?, 'hex'), p_user_fingerprint => decode(?, 'hex'),"
                ." p_fingerprints => array[decode(?, 'hex'), decode(?, 'hex'), decode(?, 'hex'), decode(?, 'hex')]::bytea[])",
                $flat,
            );
            $this->assertSame([
                str_repeat('01', 32), str_repeat('03', 32), str_repeat('04', 32),
                str_repeat('aa', 32), str_repeat('bb', 32), str_repeat('cc', 32), str_repeat('dd', 32),
            ], $bindings);

            return true;
        })->andReturn([
            (object) ['fingerprint' => str_repeat('dd', 32), 'state' => 'registered'],
            (object) ['fingerprint' => str_repeat('aa', 32), 'state' => 'new'],
            (object) ['fingerprint' => str_repeat('cc', 32), 'state' => 'held'],
            (object) ['fingerprint' => str_repeat('bb', 32), 'state' => 'reattachable'],
        ]);

        $states = self::statesOf($db, [$a, $b, $c, $d]);

        $this->assertSame(AccountState::New, $states[$a]);
        $this->assertSame(AccountState::Reattachable, $states[$b]);
        $this->assertSame(AccountState::Held, $states[$c]);
        $this->assertSame(AccountState::Registered, $states[$d]);
        $this->assertCount(4, $states);
    }

    public function test_fifty_accounts_are_asked_about_in_one_call(): void
    {
        $fingerprints = array_map(fn (int $i) => hash('sha256', (string) $i, true), range(1, 50));
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->andReturnUsing(fn (string $sql, array $bindings) => array_map(
            fn (string $hex) => (object) ['fingerprint' => $hex, 'state' => 'new'],
            array_slice($bindings, 3),
        ));

        $this->assertCount(50, self::statesOf($db, $fingerprints));
    }

    public function test_more_than_fifty_accounts_never_reach_the_database(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldNotReceive('select');

        $this->expectException(\InvalidArgumentException::class);
        self::statesOf($db, array_map(fn (int $i) => hash('sha256', (string) $i, true), range(1, 51)));
    }

    public function test_no_fingerprints_never_reach_the_database(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldNotReceive('select');

        $this->assertSame([], self::statesOf($db, []));
    }

    /**
     * @return iterable<string, array{list<object>}>
     */
    public static function brokenStateAnswers(): iterable
    {
        $a = str_repeat('aa', 32);
        $b = str_repeat('bb', 32);

        yield 'an account missing' => [[(object) ['fingerprint' => $a, 'state' => 'new']]];
        yield 'an account twice' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => $a, 'state' => 'held']]];
        yield 'an account nobody asked about' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => str_repeat('cc', 32), 'state' => 'new']]];
        yield 'an unknown state' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => $b, 'state' => 'paused']]];
        yield 'a state in another case' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => $b, 'state' => 'HELD']]];
        yield 'a null state' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => $b, 'state' => null]]];
        yield 'uppercase hex' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => strtoupper($b), 'state' => 'new']]];
        yield 'raw bytes instead of hex' => [[(object) ['fingerprint' => $a, 'state' => 'new'], (object) ['fingerprint' => str_repeat("\xbb", 32), 'state' => 'new']]];
        yield 'no rows' => [[]];
    }

    /**
     * @param  list<object>  $rows
     */
    #[DataProvider('brokenStateAnswers')]
    public function test_a_state_answer_that_breaks_the_contract_is_never_trusted(array $rows): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn($rows);

        try {
            self::statesOf($db, [str_repeat("\xaa", 32), str_repeat("\xbb", 32)]);
            $this->fail('expected a contract violation');
        } catch (RegistrationStoreUnavailable $exception) {
            $this->assertSame('contract', $exception->sqlState);
        }
    }

    /**
     * @return iterable<string, array{string, RejectionReason}>
     */
    public static function stateRejections(): iterable
    {
        yield 'code no longer usable' => ['ERROR:  register_code_unusable', RejectionReason::CodeUnusable];
        yield 'too many or malformed fingerprints' => ['ERROR:  invalid_accounts', RejectionReason::InvalidAccounts];
        yield 'the code spent its state budget' => ["ERROR:  states_budget_exhausted\nCONTEXT:  PL/pgSQL function registration_account_states", RejectionReason::StatesBudgetExhausted];
    }

    #[DataProvider('stateRejections')]
    public function test_account_state_refusals_are_named(string $message, RejectionReason $reason): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException('P0001', $message));

        try {
            self::statesOf($db, [str_repeat("\xaa", 32)]);
            $this->fail('expected a rejection');
        } catch (RegistrationRejected $rejection) {
            $this->assertSame($reason, $rejection->reason);
        }
    }

    public function test_the_budget_refusal_row_is_a_named_rejection_logged_with_the_number_of_accounts_only(): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = [$message->level, $message->message, $message->context];
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->andReturn([(object) ['fingerprint' => null, 'state' => 'budget_exhausted']]);

        try {
            self::statesOf($db, [str_repeat("\xaa", 32), str_repeat("\xbb", 32), str_repeat("\xcc", 32)]);
            $this->fail('expected a rejection');
        } catch (RegistrationRejected $rejection) {
            $this->assertSame(RejectionReason::StatesBudgetExhausted, $rejection->reason);
        }

        $this->assertSame([['warning', 'registration_account_states refused: states_budget_exhausted', ['fingerprints' => 3]]], $logged);
    }

    /**
     * @return iterable<string, array{list<object>}>
     */
    public static function malformedBudgetRefusals(): iterable
    {
        $a = str_repeat('aa', 32);

        yield 'refusal with a fingerprint' => [[(object) ['fingerprint' => $a, 'state' => 'budget_exhausted']]];
        yield 'refusal next to an answer' => [[(object) ['fingerprint' => null, 'state' => 'budget_exhausted'], (object) ['fingerprint' => $a, 'state' => 'new']]];
        yield 'refusal twice' => [[(object) ['fingerprint' => null, 'state' => 'budget_exhausted'], (object) ['fingerprint' => null, 'state' => 'budget_exhausted']]];
        yield 'null fingerprint with a real state' => [[(object) ['fingerprint' => null, 'state' => 'new']]];
        yield 'refusal in another case' => [[(object) ['fingerprint' => null, 'state' => 'BUDGET_EXHAUSTED']]];
    }

    /**
     * @param  list<object>  $rows
     */
    #[DataProvider('malformedBudgetRefusals')]
    public function test_a_malformed_budget_refusal_is_a_contract_violation(array $rows): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn($rows);

        try {
            self::statesOf($db, [str_repeat("\xaa", 32)]);
            $this->fail('expected a contract violation');
        } catch (RegistrationStoreUnavailable $exception) {
            $this->assertSame('contract', $exception->sqlState);
        }
    }

    public function test_the_older_raised_budget_refusal_is_still_mapped_and_logged(): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = [$message->level, $message->message, $message->context];
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException('P0001', 'ERROR:  states_budget_exhausted'));

        try {
            self::statesOf($db, [str_repeat("\xaa", 32), str_repeat("\xbb", 32)]);
            $this->fail('expected a rejection');
        } catch (RegistrationRejected $rejection) {
            $this->assertSame(RejectionReason::StatesBudgetExhausted, $rejection->reason);
        }

        $this->assertSame([['warning', 'registration_account_states refused: states_budget_exhausted', ['fingerprints' => 2]]], $logged);
    }

    public function test_other_state_refusals_are_not_logged_as_budget_refusals(): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message;
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andThrow(self::queryException('P0001', 'ERROR:  register_code_unusable'));

        try {
            self::statesOf($db, [str_repeat("\xaa", 32)]);
        } catch (RegistrationRejected) {
        }

        $this->assertSame([], $logged);
    }

    public function test_user_bound_is_a_state_of_the_contract(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) ['fingerprint' => str_repeat('aa', 32), 'state' => 'user_bound']]);

        $this->assertSame([str_repeat("\xaa", 32) => AccountState::UserBound], self::statesOf($db, [str_repeat("\xaa", 32)]));
    }

    public function test_catch_up_days_come_back_with_every_row(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->withArgs(function (string $sql) {
            $this->assertMatchesRegularExpression('/as registered_at,\s+catchup_days,\s/', $sql);

            return true;
        })->andReturn([
            (object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => null, 'registered_at' => '2026-09-01T00:00:00Z', 'catchup_days' => 14, ...self::NO_HANDOVER],
            (object) ['account_id' => 'acc-2', 'reattached' => false, 'last_success_at' => null, 'registered_at' => null, 'catchup_days' => 14, ...self::NO_HANDOVER],
        ]);

        $result = (new PostgresRegistrationStore($db))->register($this->registration());

        $this->assertSame([14, 14], [$result[0]->catchUpDays, $result[1]->catchUpDays]);
    }

    public function test_the_hand_over_columns_are_selected_by_name(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->once()->withArgs(function (string $sql) {
            $flat = (string) preg_replace('/\s+/', ' ', $sql);
            $this->assertStringContainsString("catchup_days, to_char(gap_from at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as gap_from,"
                ." to_char(gap_to at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as gap_to, handover, gap_delivered_count, gap_pending_count from register_connection(", $flat);

            return true;
        })->andReturn([
            (object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => null, 'registered_at' => '2026-09-01T00:00:00Z', 'catchup_days' => 7,
                'gap_from' => '2026-10-01T03:04:05Z', 'gap_to' => '2026-10-16T01:55:00Z', 'handover' => true, 'gap_delivered_count' => 3, 'gap_pending_count' => 2],
        ]);

        $row = (new PostgresRegistrationStore($db))->register($this->registration())[0];

        $this->assertTrue($row->handover);
        $this->assertSame('2026-10-01T03:04:05+00:00', $row->gapFrom?->format(DATE_ATOM));
        $this->assertSame('2026-10-16T01:55:00+00:00', $row->gapTo?->format(DATE_ATOM));
        $this->assertSame(3, $row->gapDeliveredCount);
        $this->assertSame(2, $row->gapPendingCount);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function brokenHandOverColumns(): iterable
    {
        foreach (['gap_from', 'gap_to', 'handover', 'gap_delivered_count', 'gap_pending_count'] as $column) {
            $row = self::NO_HANDOVER;
            unset($row[$column]);
            yield "{$column} missing" => [$row];
        }
        yield 'handover as text' => [[...self::NO_HANDOVER, 'handover' => 'f']];
        yield 'handover null' => [[...self::NO_HANDOVER, 'handover' => null]];
    }

    /**
     * The schema is pinned: a row without the hand-over columns means the
     * database is not the one this site was built for.
     *
     * @param  array<string, mixed>  $columns
     */
    #[DataProvider('brokenHandOverColumns')]
    public function test_missing_or_mistyped_hand_over_columns_are_a_contract_violation(array $columns): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) [
            'account_id' => 'acc-1', 'reattached' => false, 'last_success_at' => null, 'registered_at' => null, 'catchup_days' => 7, ...$columns,
        ]]);

        try {
            (new PostgresRegistrationStore($db))->register($this->registration());
            $this->fail('expected a contract violation');
        } catch (RegistrationStoreUnavailable $exception) {
            $this->assertSame('contract', $exception->sqlState);
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool, ?int, ?int, bool}>
     */
    public static function handOverGaps(): iterable
    {
        $gap = ['gap_from' => '2026-10-01T03:04:05Z', 'gap_to' => '2026-10-16T01:55:00Z'];
        $none = ['gap_delivered_count' => null, 'gap_pending_count' => null];
        $zero = ['gap_delivered_count' => 0, 'gap_pending_count' => 0];

        yield 'no gap' => [['gap_from' => null, 'gap_to' => null, ...$none], false, null, null, false];
        yield 'empty gap' => [['gap_from' => '2026-10-01T00:00:00Z', 'gap_to' => '2026-10-01T00:00:00Z', ...$zero], false, null, null, false];
        yield 'counts zero' => [[...$gap, ...$zero], true, 0, 0, false];
        yield 'counts' => [[...$gap, 'gap_delivered_count' => 4, 'gap_pending_count' => 2], true, 4, 2, false];
        yield 'counts as text' => [[...$gap, 'gap_delivered_count' => '12', 'gap_pending_count' => '3'], true, 12, 3, false];
        yield 'delivered unreadable' => [[...$gap, 'gap_delivered_count' => 'many', 'gap_pending_count' => 1], true, null, 1, true];
        yield 'pending unreadable' => [[...$gap, 'gap_delivered_count' => 1, 'gap_pending_count' => 'some'], true, 1, null, true];
        yield 'delivered negative' => [[...$gap, 'gap_delivered_count' => -1, 'gap_pending_count' => 0], true, null, 0, true];
        yield 'pending negative' => [[...$gap, 'gap_delivered_count' => 0, 'gap_pending_count' => -1], true, 0, null, true];
        yield 'counts null' => [[...$gap, ...$none], true, null, null, true];
        yield 'only the start' => [['gap_from' => '2026-10-01T03:04:05Z', 'gap_to' => null, ...$zero], false, null, null, true];
        yield 'only the end' => [['gap_from' => null, 'gap_to' => '2026-10-01T03:04:05Z', ...$zero], false, null, null, true];
        yield 'inverted' => [['gap_from' => '2026-10-02T00:00:00Z', 'gap_to' => '2026-10-01T00:00:00Z', ...$zero], false, null, null, true];
        yield 'unreadable time' => [['gap_from' => 'yesterday', 'gap_to' => '2026-10-01T00:00:00Z', ...$zero], false, null, null, true];
    }

    /**
     * @param  array<string, mixed>  $columns
     */
    #[DataProvider('handOverGaps')]
    public function test_a_hand_over_gap_value_never_fails_a_committed_registration(array $columns, bool $hasGap, ?int $delivered, ?int $pending, bool $warned): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message;
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) [
            'account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => null, 'registered_at' => null, 'catchup_days' => 7, 'handover' => true, ...$columns,
        ]]);

        $row = (new PostgresRegistrationStore($db))->register($this->registration())[0];

        $this->assertTrue($row->handover, 'a hand-over stays a hand-over whatever its gap');
        $this->assertSame($hasGap, $row->gapFrom !== null && $row->gapTo !== null);
        $this->assertSame($delivered, $row->gapDeliveredCount);
        $this->assertSame($pending, $row->gapPendingCount);
        $this->assertSame($warned, $logged !== [], implode(', ', $logged));
    }

    public function test_gap_values_on_a_row_that_is_not_a_hand_over_are_ignored(): void
    {
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([(object) [
            'account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => null, 'registered_at' => null, 'catchup_days' => 7,
            'gap_from' => '2026-10-01T03:04:05Z', 'gap_to' => '2026-10-16T01:55:00Z', 'handover' => false, 'gap_delivered_count' => 2, 'gap_pending_count' => 1,
        ]]);

        $row = (new PostgresRegistrationStore($db))->register($this->registration())[0];

        $this->assertFalse($row->handover);
        $this->assertNull($row->gapFrom);
        $this->assertNull($row->gapDeliveredCount);
    }

    private const string UNREADABLE = 'register_connection returned an unreadable value {"column":"catchup_days"}';

    private const string NOT_AUDITED = 'register_connection returned no audited catch-up limit; the wrapbiz operator must run '
        .'migrate verify {"column":"catchup_days"}';

    /**
     * @return iterable<string, array{mixed, ?int, ?string}>
     */
    public static function catchUpDayValues(): iterable
    {
        yield 'minimum' => [1, 1, null];
        yield 'maximum' => [31, 31, null];
        yield 'digits as text' => ['7', 7, null];
        yield 'zero' => [0, null, self::UNREADABLE];
        yield 'negative' => [-7, null, self::UNREADABLE];
        yield 'above the worker maximum' => [32, null, self::UNREADABLE];
        yield 'NULL: no audited limit (wrapbiz round 27)' => [null, null, self::NOT_AUDITED];
        yield 'fraction' => [7.5, null, self::UNREADABLE];
        yield 'text' => ['seven', null, self::UNREADABLE];
        yield 'padded text' => [' 7', null, self::UNREADABLE];
        yield 'boolean' => [true, null, self::UNREADABLE];
    }

    #[DataProvider('catchUpDayValues')]
    public function test_an_unreadable_catch_up_window_never_fails_a_committed_registration(mixed $value, ?int $expected, ?string $log): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message.' '.json_encode($message->context);
        });
        $db = Mockery::mock(ConnectionInterface::class);
        $db->shouldReceive('select')->andReturn([
            (object) ['account_id' => 'acc-1', 'reattached' => true, 'last_success_at' => '2026-01-01T00:00:00Z', 'registered_at' => '2025-12-01T00:00:00Z', 'catchup_days' => $value, ...self::NO_HANDOVER],
        ]);

        $result = (new PostgresRegistrationStore($db))->register($this->registration());

        $this->assertSame($expected, $result[0]->catchUpDays);
        if ($log !== null) {
            $this->assertContains($log, $logged);
        } else {
            $this->assertSame([], $logged);
        }
    }
}
