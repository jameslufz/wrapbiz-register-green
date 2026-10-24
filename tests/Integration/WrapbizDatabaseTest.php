<?php

namespace Tests\Integration;

use App\Kbiz\BankAccount;
use App\Kbiz\BankSession;
use App\Registration\Registrar;
use App\Security\AccountNumber;
use App\Wrapbiz\AccountState;
use App\Wrapbiz\AttemptReservation;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\NewAccount;
use App\Wrapbiz\NewRegistration;
use App\Wrapbiz\PostgresRegistrationStore;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use App\Wrapbiz\RejectionReason;
use Illuminate\Database\QueryException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use PDO;
use Tests\Support\FakeBank;
use Tests\TestCase;

/**
 * Runs the real registration functions (contract B) through a login role
 * that only has the registration group role's rights, in a scratch database
 * that is created and dropped here. Every test migrates for its own random
 * bank name, so its group roles (wrapbiz_<bank>_*) are its own too: no test
 * login ever joins a real bank's roles, and all of them are dropped again.
 *
 * Opt-in: WRAPBIZ_TEST_PG_ADMIN_DSN="pgsql:host=127.0.0.1;port=5433;dbname=postgres"
 *         WRAPBIZ_TEST_PG_ADMIN_USER, WRAPBIZ_TEST_PG_ADMIN_PASSWORD
 *         WRAPBIZ_TEST_MIGRATION (path to wrapbiz migrations/0001_init.sql): every
 *         migration of that directory is applied in order, and the catch-up limit
 *         is recorded in the audit log, as `wrapbiz-<bank> migrate up` does
 */
final class WrapbizDatabaseTest extends TestCase
{
    /** What the scratch migration bakes in as the worker's POLL_CATCHUP_MAX_DAYS. */
    private const int CATCHUP_DAYS = 9;

    private ?PDO $admin = null;

    private string $bank = '';

    private string $database = '';

    private string $role = '';

    /** @var list<string> further login roles a test created; dropped in tearDown */
    private array $extraLogins = [];

    private string $scratchDsn = '';

    private string $adminUser = '';

    private string $adminPassword = '';

    /** @var array{host: string, port: string, password: string} */
    private array $registrationLogin = ['host' => '', 'port' => '', 'password' => ''];

    protected function setUp(): void
    {
        parent::setUp();

        $dsn = getenv('WRAPBIZ_TEST_PG_ADMIN_DSN') ?: '';
        $migration = getenv('WRAPBIZ_TEST_MIGRATION') ?: '';
        if ($dsn === '' || ! is_file($migration)) {
            $this->markTestSkipped('Set WRAPBIZ_TEST_PG_ADMIN_DSN and WRAPBIZ_TEST_MIGRATION to run against PostgreSQL.');
        }

        $this->adminUser = getenv('WRAPBIZ_TEST_PG_ADMIN_USER') ?: 'postgres';
        $this->adminPassword = getenv('WRAPBIZ_TEST_PG_ADMIN_PASSWORD') ?: '';
        $suffix = bin2hex(random_bytes(6));
        $this->bank = 'test'.$suffix;
        $this->database = 'wrapbiz_test_'.$suffix;
        $this->role = 'wrapbiz_reg_test_'.$suffix;
        $rolePassword = bin2hex(random_bytes(16));

        $this->admin = new PDO($dsn, $this->adminUser, $this->adminPassword, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->admin->exec("create database {$this->database}");

        $this->scratchDsn = preg_replace('/dbname=[^;]+/', 'dbname='.$this->database, $dsn) ?? $dsn;
        $owner = $this->owner();
        // `wrapbiz-<bank> migrate` passes these as startup parameters.
        $owner->exec("set wrapbiz.bank = '{$this->bank}'");
        $owner->exec("set wrapbiz.catchup_days = '".self::CATCHUP_DAYS."'");
        foreach (self::migrations($migration) as $file) {
            $owner->exec(self::gooseUp((string) file_get_contents($file)));
        }
        $owner->exec("insert into audit_log (actor, action, detail) values ('migrate', 'catchup_days.changed',
            jsonb_build_object('from', null, 'to', ".self::CATCHUP_DAYS.'))');
        // Exactly the README's setup: CONNECT comes from the group role only.
        $owner->exec("create role {$this->role} login password '{$rolePassword}' in role wrapbiz_{$this->bank}_registration");

        preg_match('/host=([^;]+)/', $dsn, $host);
        preg_match('/port=([^;]+)/', $dsn, $port);
        $this->registrationLogin = ['host' => $host[1] ?? '127.0.0.1', 'port' => $port[1] ?? '5432', 'password' => $rolePassword];
        config(['database.connections.wrapbiz' => array_merge(config('database.connections.wrapbiz'), [
            'url' => null,
            'host' => $host[1] ?? '127.0.0.1',
            'port' => $port[1] ?? '5432',
            'database' => $this->database,
            'username' => $this->role,
            'password' => $rolePassword,
            'sslmode' => 'disable',
        ])]);
        DB::purge('wrapbiz');
        $this->app->instance(RegistrationStore::class, $this->store());
        $this->app->when(Registrar::class)->needs('$provider')->give($this->bank);
    }

    protected function tearDown(): void
    {
        if ($this->admin !== null) {
            DB::purge('wrapbiz');
            $this->admin->exec("drop database if exists {$this->database} with (force)");
            $this->admin->exec("drop role if exists {$this->role}");
            foreach ($this->extraLogins as $login) {
                $this->admin->exec("drop role if exists {$login}");
            }
            $bankRoles = $this->admin->prepare("select rolname from pg_roles where rolname like ? escape '!'");
            $bankRoles->execute(['wrapbiz!_'.$this->bank.'!_%']);
            foreach ($bankRoles->fetchAll(PDO::FETCH_COLUMN) as $bankRole) {
                $this->admin->exec('drop role if exists "'.$bankRole.'"');
            }
            $this->admin = null;
        }

        parent::tearDown();
    }

    /**
     * The migrations in the directory of $first (wrapbiz's 0001_init.sql), in
     * goose's order.
     *
     * @return list<string>
     */
    private static function migrations(string $first): array
    {
        $files = glob(dirname($first).'/[0-9][0-9][0-9][0-9]_*.sql') ?: [];
        sort($files, SORT_STRING);

        return $files;
    }

    private static function gooseUp(string $sql): string
    {
        $up = explode('-- +goose Down', explode('-- +goose Up', $sql, 2)[1] ?? '', 2)[0];

        return (string) preg_replace('/^-- \+goose Statement(Begin|End)\s*$/m', '', $up);
    }

    private function owner(): PDO
    {
        return new PDO($this->scratchDsn, $this->adminUser, $this->adminPassword, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }

    private function addCode(string $code): string
    {
        $this->owner()->prepare("insert into register_codes (code_hash) values (decode(?, 'hex'))")->execute([hash('sha256', $code)]);

        return hash('sha256', $code, true);
    }

    private function store(): PostgresRegistrationStore
    {
        return new PostgresRegistrationStore(DB::connection('wrapbiz'));
    }

    /**
     * @param  list<string>  $fingerprints  raw 32-byte fingerprints
     */
    private function registration(string $codeHash, array $fingerprints, string $orgFingerprint, string $webhook = 'https://hooks.example.com/a', ?string $userFingerprint = null, ?string $provider = null): NewRegistration
    {
        sort($fingerprints, SORT_STRING);

        return new NewRegistration(
            codeHash: $codeHash,
            provider: $provider ?? $this->bank,
            webhookUrl: $webhook,
            connectionId: (string) Str::uuid7(),
            sealedCredential: random_bytes(80),
            orgFingerprint: $orgFingerprint,
            userFingerprint: $userFingerprint ?? random_bytes(32),
            accounts: array_map(fn (string $fingerprint) => new NewAccount((string) Str::uuid7(), $fingerprint, 'xxx-x-x1234-x', random_bytes(70)), $fingerprints),
            ipHash: random_bytes(32),
        );
    }

    /**
     * @return string the raw fingerprint of a fresh account registered by a fresh user
     */
    private function registeredByAnotherUser(): string
    {
        $fingerprint = random_bytes(32);
        $this->store()->register($this->registration($this->addCode('code-other-'.bin2hex(random_bytes(6))), [$fingerprint], random_bytes(32)));

        return $fingerprint;
    }

    private function assertRejected(RejectionReason $reason, callable $call, string $message = ''): void
    {
        try {
            $call();
            $this->fail("expected {$reason->value}".($message === '' ? '' : ": {$message}"));
        } catch (RegistrationRejected $rejection) {
            $this->assertSame($reason, $rejection->reason, $message);
        }
    }

    /**
     * Simulates the worker noticing an expired bank session: both rows go to
     * "expired" and every secret is wiped, as the schema requires.
     *
     * @param  list<string>  $accountIds
     */
    private function expire(array $accountIds): void
    {
        $owner = $this->owner();
        $in = implode(',', array_map(fn (string $id) => $owner->quote($id), $accountIds));
        $owner->exec("update connections set status = 'expired', expired_at = now(), credential_format = null,
                             credential_key_id = null, credential_nonce = null, credential_ciphertext = null
                       where id in (select connection_id from accounts where id in ({$in}))");
        $owner->exec("update accounts set status = 'expired', secret_format = null, secret_key_id = null,
                             secret_nonce = null, secret_ciphertext = null, secret_seal_id = null
                       where id in ({$in})");
    }

    public function test_code_status_lifecycle(): void
    {
        $store = $this->store();
        $usable = $this->addCode('code-usable-0123456789');
        $expired = $this->addCode('code-expired-0123456789');
        $this->owner()->exec("update register_codes set expires_at = now() - interval '1 minute' where code_hash = decode('".bin2hex($expired)."', 'hex')");

        $this->assertSame(CodeStatus::Usable, $store->codeStatus($usable));
        $this->assertSame(CodeStatus::Unknown, $store->codeStatus(hash('sha256', 'never-issued', true)));
        $this->assertSame(CodeStatus::Expired, $store->codeStatus($expired));

        $store->register($this->registration($usable, [random_bytes(32)], random_bytes(32)));
        $this->assertSame(CodeStatus::Used, $store->codeStatus($usable));

        $this->owner()->exec("update register_codes set expires_at = now() - interval '1 minute' where code_hash = decode('".bin2hex($usable)."', 'hex')");
        $this->assertSame(CodeStatus::Used, $store->codeStatus($usable), 'a used code stays "used" after it would have expired');
    }

    public function test_code_locks_after_five_failed_logins(): void
    {
        $store = $this->store();
        $code = $this->addCode('code-lock-0123456789');

        for ($i = 1; $i < 5; $i++) {
            $this->assertFalse($store->recordFailedLogin($code, null), "failure {$i}");
        }
        $this->assertTrue($store->recordFailedLogin($code, null));
        $this->assertSame(CodeStatus::Locked, $store->codeStatus($code));

        $this->assertRejected(RejectionReason::CodeUnusable, fn () => $store->register($this->registration($code, [random_bytes(32)], random_bytes(32))));
    }

    public function test_registration_rules(): void
    {
        $store = $this->store();
        $fingerprint = random_bytes(32);
        $first = $this->registration($this->addCode('code-one-0123456789'), [$fingerprint], random_bytes(32));

        $created = $store->register($first);
        $this->assertSame($first->accounts[0]->id, $created[0]->id);
        $this->assertFalse($created[0]->reattached);

        $this->assertRejected(RejectionReason::CodeUnusable, fn () => $store->register($this->registration($first->codeHash, [random_bytes(32)], random_bytes(32))));

        $second = $this->addCode('code-two-0123456789');
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [], random_bytes(32))));
        $duplicate = random_bytes(32);
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [$duplicate, $duplicate], random_bytes(32))));
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [random_bytes(32), random_bytes(32)], random_bytes(32))), 'exactly one account per registration');
        $this->assertRejected(RejectionReason::UserAlreadyRegistered, fn () => $store->register($this->registration($second, [random_bytes(32)], $first->orgFingerprint, userFingerprint: $first->userFingerprint)));
        $this->assertRejected(RejectionReason::UserAlreadyRegistered, fn () => $store->register($this->registration($second, [$this->registeredByAnotherUser()], $first->orgFingerprint, userFingerprint: $first->userFingerprint)), 'the user rule comes before the account rule');
        $this->assertRejected(RejectionReason::AccountAlreadyRegistered, fn () => $store->register($this->registration($second, [$fingerprint], $first->orgFingerprint)));
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [random_bytes(32)], random_bytes(31))));
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [random_bytes(32)], random_bytes(32), userFingerprint: random_bytes(31))));
        $this->assertRejected(RejectionReason::InvalidInput, fn () => $store->register($this->registration($second, [random_bytes(32)], random_bytes(32), 'http://hooks.example.com/a')));
        $this->assertRejected(RejectionReason::InvalidAccounts, fn () => $store->register($this->registration($second, [random_bytes(32)], random_bytes(32), provider: 'scb')));
        $this->assertSame(CodeStatus::Usable, $store->codeStatus($second), 'every rejection rolled back');

        $sameRefOtherOrg = $store->register($this->registration($second, [random_bytes(32)], random_bytes(32), userFingerprint: $first->userFingerprint));
        $this->assertCount(1, $sameRefOtherOrg, 'a user is the pair of organisation and user reference');
    }

    public function test_an_expired_account_is_reattached_by_its_user_and_shown_with_its_number(): void
    {
        $session = new BankSession('token', 'user', 'ORG-1', 'C');
        $registrar = $this->app->make(Registrar::class);

        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);

        $code = $this->addCode('code-two-0123456789');
        $this->assertRejected(RejectionReason::UserAlreadyRegistered, fn () => $registrar->register($code, 'https://hooks.example.com/b', $session,
            self::account('2222222222'), '198.51.100.1'), 'a user never gets a second account, not even while its first is expired');
        $results = $registrar->register($code, 'https://hooks.example.com/b', $session, self::account('1111111111'), '198.51.100.1');

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->reattached);
        $this->assertSame($original[0]->accountId, $results[0]->accountId);
        $this->assertSame('xxx-x-x1111-x', $results[0]->maskedNumber);
        $urls = $this->owner()->query('select distinct w.url from accounts a join connections c on c.id = a.connection_id join webhook_endpoints w on w.id = c.endpoint_id')->fetchAll(PDO::FETCH_COLUMN);
        $this->assertSame(['https://hooks.example.com/b'], $urls, 'the existing endpoint now uses the new URL');
    }

    public function test_reattach_requires_the_same_organisation(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $original = $registrar->register(
            $this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'u', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1',
        );
        $this->expire([$original[0]->accountId]);

        $this->assertRejected(RejectionReason::AccountAlreadyRegistered, fn () => $registrar->register(
            $this->addCode('code-two-0123456789'), 'https://hooks.example.com/b', new BankSession('t', 'u', 'ORG-2', 'C'),
            self::account('1111111111'), '198.51.100.1',
        ));
    }

    public function test_full_http_flow_stores_only_sealed_data(): void
    {
        $this->addCode('code-http-0123456789');
        $this->reachAccountSelection('code-http-0123456789');

        $this->post('/accounts', ['list' => session('registration.list_nonce'), 'account' => session('registration.accounts')[0]['token']])
            ->assertOk()
            ->assertSee('ลงทะเบียนสำเร็จ');

        $owner = $this->owner();
        $connection = $owner->query('select * from connections')->fetch();
        $credential = json_decode((string) sodium_crypto_box_seal_open(stream_get_contents($connection['credential_ciphertext']), $this->sealSecretKeypair), true);
        $this->assertSame($connection['id'], $credential['connection_id']);
        $this->assertSame(hash_hmac('sha256', $this->bank.':org:ORG-9', str_repeat('f', 32)), bin2hex(stream_get_contents($connection['org_fingerprint'])));

        $accounts = $owner->query('select * from accounts order by account_no_masked')->fetchAll();
        $this->assertSame(['xxx-x-x6789-x'], array_column($accounts, 'account_no_masked'));
        foreach ($accounts as $account) {
            $secret = json_decode((string) sodium_crypto_box_seal_open(stream_get_contents($account['secret_ciphertext']), $this->sealSecretKeypair), true);
            $this->assertSame($account['id'], $secret['account_id']);
            $this->assertSame($account['id'], $account['secret_seal_id']);
        }
    }

    public function test_five_wrong_bank_logins_lock_the_code_in_the_database(): void
    {
        $code = $this->addCode('code-lock-http-0123456789');
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => 'code-lock-http-0123456789'])->assertRedirect('/login');

        for ($i = 1; $i <= 5; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])->from('/login')
                ->post('/login', ['username' => 'u', 'password' => 'wrong', 'webhook_url' => 'https://hooks.example.com/a']);
        }

        $this->assertSame(CodeStatus::Locked, $this->store()->codeStatus($code));
        $this->assertSame(5, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count());
        $this->assertSame(1, (int) $this->owner()->query("select count(*) from audit_log where action = 'register_code.locked'")->fetchColumn());
    }

    public function test_bug_003_a_response_lost_after_commit_is_reported_as_possibly_completed(): void
    {
        $this->addCode('code-lost-0123456789');
        $real = $this->store();
        $this->app->instance(RegistrationStore::class, new class($real) implements RegistrationStore
        {
            public function __construct(private RegistrationStore $inner) {}

            public function codeStatus(string $codeHash): CodeStatus
            {
                return $this->inner->codeStatus($codeHash);
            }

            public function beginLoginAttempt(string $codeHash): AttemptReservation
            {
                return $this->inner->beginLoginAttempt($codeHash);
            }

            public function endLoginAttempt(string $codeHash, string $reservationId): void
            {
                $this->inner->endLoginAttempt($codeHash, $reservationId);
            }

            public function recordFailedLogin(string $codeHash, ?string $reservationId): bool
            {
                return $this->inner->recordFailedLogin($codeHash, $reservationId);
            }

            public function accountStates(string $codeHash, string $orgFingerprint, string $userFingerprint, array $fingerprints): array
            {
                return $this->inner->accountStates($codeHash, $orgFingerprint, $userFingerprint, $fingerprints);
            }

            public function register(NewRegistration $registration): array
            {
                $this->inner->register($registration);

                throw new RegistrationStoreUnavailable('08006');
            }
        });
        $this->reachAccountSelection('code-lost-0123456789');

        $this->post('/accounts', ['list' => session('registration.list_nonce'), 'account' => session('registration.accounts')[0]['token']])
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => CodeStatus::Used->message()]);
        $this->assertSame(1, (int) $this->owner()->query('select count(*) from connections')->fetchColumn());
    }

    public function test_registration_role_cannot_read_tables(): void
    {
        $this->expectException(QueryException::class);
        $this->expectExceptionMessage('permission denied');

        DB::connection('wrapbiz')->select('select * from accounts');
    }

    public function test_reattach_requires_the_same_bank_user(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $original = $registrar->register(
            $this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'USER-1', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1',
        );
        $this->expire([$original[0]->accountId]);

        $this->assertRejected(RejectionReason::AccountAlreadyRegistered, fn () => $registrar->register(
            $this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'USER-2', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1',
        ));

        $again = $registrar->register(
            $this->addCode('code-three-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'USER-1', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1',
        );
        $this->assertTrue($again[0]->reattached);
        $this->assertSame($original[0]->accountId, $again[0]->accountId);

        $stored = $this->owner()->query("select encode(c.user_fingerprint, 'hex') from accounts a join connections c on c.id = a.connection_id where a.id = ".$this->owner()->quote($again[0]->accountId))->fetchColumn();
        $this->assertSame(hash_hmac('sha256', $this->bank.':user:USER-1', str_repeat('f', 32)), $stored);
    }

    public function test_a_reattached_row_returns_the_kept_watermark(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);
        $this->owner()->exec("update accounts set last_success_at = '2026-09-30T10:15:00Z'");

        $again = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1')[0];

        $this->assertTrue($again->reattached);
        $this->assertSame('2026-09-30 17:15', $again->missed?->from->format('Y-m-d H:i'));
        // The reach day, 16 - N - 1, is still fetched (wrapbiz core.ReachDay).
        $this->assertSame('2026-10-'.sprintf('%02d', 16 - self::CATCHUP_DAYS - 2), $again->missed?->lastMissedDay->format('Y-m-d'));
    }

    /** BUG-R3-03 */
    public function test_a_never_polled_reattached_account_reports_the_range_since_its_registration(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session,
            self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);
        $owner = $this->owner();
        $owner->exec('set session_replication_role = replica');
        $owner->exec("update accounts set created_at = now() - interval '20 days'");
        $owner->exec('set session_replication_role = origin');
        $registeredAt = new \DateTimeImmutable((string) $owner->query("select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') from accounts")->fetchColumn());

        $again = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', $session,
            self::account('1111111111'), '198.51.100.1');

        $this->assertTrue($again[0]->reattached);
        $this->assertNotNull($again[0]->missed);
        $this->assertSame($registeredAt->setTimezone(new \DateTimeZone('Asia/Bangkok'))->format('Y-m-d H:i'), $again[0]->missed->from->format('Y-m-d H:i'));
        $this->assertSame(now('Asia/Bangkok')->startOfDay()->subDays(self::CATCHUP_DAYS + 2)->format('Y-m-d'), $again[0]->missed->lastMissedDay->format('Y-m-d'));
    }

    /** SEC-R2-01 */
    public function test_attempt_reservations_count_towards_the_lock_limit(): void
    {
        $store = $this->store();
        $code = $this->addCode('code-attempts-0123456789');

        $ids = [];
        for ($i = 1; $i <= 5; $i++) {
            $ids[] = $this->reserve($store, $code);
        }
        $this->assertCount(5, array_unique($ids));
        $this->assertSame(LoginAttempt::Busy, $store->beginLoginAttempt($code)->attempt);
        $this->assertNull($store->beginLoginAttempt($code)->reservationId, 'only ok carries a reservation');
        $this->assertSame(CodeStatus::Usable, $store->codeStatus($code), 'busy is not a code state');

        $store->endLoginAttempt($code, $ids[0]);
        $ids[] = $this->reserve($store, $code);
        $this->assertSame(LoginAttempt::Busy, $store->beginLoginAttempt($code)->attempt);

        $store->endLoginAttempt($code, $ids[0]);
        $store->endLoginAttempt($code, '0199f2a4-5b6c-7d8e-9f00-0000000000ff');
        $other = $this->addCode('code-other-0123456789');
        $store->endLoginAttempt($other, $ids[1]);
        $this->assertSame(LoginAttempt::Busy, $store->beginLoginAttempt($code)->attempt, 'a released, unknown or foreign id frees nothing');

        $this->assertFalse($store->recordFailedLogin($code, $ids[1]), 'a counted failure releases its slot ...');
        $this->assertSame(LoginAttempt::Busy, $store->beginLoginAttempt($code)->attempt, '... but keeps it used up');
        foreach ([$ids[2], $ids[3], $ids[4]] as $id) {
            $this->assertFalse($store->recordFailedLogin($code, $id));
        }
        $this->assertTrue($store->recordFailedLogin($code, $ids[5]), 'the fifth counted failure locks');
        $this->assertSame(LoginAttempt::Locked, $store->beginLoginAttempt($code)->attempt);
    }

    /**
     * A rejected approval is counted with no reservation (its slot was
     * released when the QR was shown) and must not take another request's.
     */
    public function test_a_rejected_approval_never_releases_another_requests_reservation(): void
    {
        $store = $this->store();
        $code = $this->addCode('code-rejected-0123456789');

        $store->endLoginAttempt($code, $this->reserve($store, $code));
        $inFlight = $this->reserve($store, $code);
        $this->assertFalse($store->recordFailedLogin($code, null));

        $this->assertSame(3, $this->drainSlots($store, $code), '1 failure + 1 live reservation of 5');
        $store->endLoginAttempt($code, $inFlight);
        $this->assertSame(1, $this->drainSlots($store, $code), 'the live reservation was still held');
    }

    public function test_begin_attempt_reports_why_a_code_is_unusable(): void
    {
        $store = $this->store();
        $this->assertSame(LoginAttempt::Unknown, $store->beginLoginAttempt(hash('sha256', 'never-issued', true))->attempt);

        $expired = $this->addCode('code-expired-0123456789');
        $this->owner()->exec("update register_codes set expires_at = now() - interval '1 minute' where code_hash = decode('".bin2hex($expired)."', 'hex')");
        $this->assertSame(LoginAttempt::Expired, $store->beginLoginAttempt($expired)->attempt);

        $used = $this->addCode('code-used-0123456789');
        $store->register($this->registration($used, [random_bytes(32)], random_bytes(32)));
        $this->assertSame(LoginAttempt::Used, $store->beginLoginAttempt($used)->attempt);

        $exhausted = $this->addCode('code-exhausted-0123456789');
        $this->spendStatesBudget($exhausted);
        $this->assertSame(LoginAttempt::Exhausted, $store->beginLoginAttempt($exhausted)->attempt);
        $this->assertSame(CodeStatus::Exhausted, $store->codeStatus($exhausted));
    }

    /**
     * SEC-R2-01 regression: separate PHP processes, each with its own
     * session, submit a wrong login for one code at the same moment. The
     * bank must see at most five credential submissions.
     */
    public function test_parallel_logins_on_one_code_reach_the_bank_at_most_five_times(): void
    {
        $racers = 10;
        $code = 'code-race-'.bin2hex(random_bytes(8));
        $codeHash = $this->addCode($code);
        $startAt = microtime(true) + 6;
        $processes = [];
        for ($i = 1; $i <= $racers; $i++) {
            $env = [
                ...getenv(),
                'WRAPBIZ_RACE_CODE' => $code,
                'WRAPBIZ_RACE_IP' => "198.51.100.{$i}",
                'WRAPBIZ_RACE_START' => (string) $startAt,
                'WRAPBIZ_RACE_DB_HOST' => $this->registrationLogin['host'],
                'WRAPBIZ_RACE_DB_PORT' => $this->registrationLogin['port'],
                'WRAPBIZ_RACE_DB_DATABASE' => $this->database,
                'WRAPBIZ_RACE_DB_USERNAME' => $this->role,
                'WRAPBIZ_RACE_DB_PASSWORD' => $this->registrationLogin['password'],
            ];
            unset($env['WRAPBIZ_TEST_PG_ADMIN_DSN'], $env['WRAPBIZ_TEST_PG_ADMIN_USER'], $env['WRAPBIZ_TEST_PG_ADMIN_PASSWORD']);
            $process = proc_open(
                [PHP_BINARY, base_path('vendor/bin/phpunit'), '--configuration', base_path('phpunit.xml'),
                    '--filter', 'test_one_racer', base_path('tests/Integration/ParallelLoginRacerTest.php')],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                base_path(),
                $env,
            );
            $this->assertIsResource($process);
            $processes[] = [$process, $pipes];
        }

        $outcomes = ['sent' => 0, 'busy' => 0, 'locked' => 0];
        foreach ($processes as [$process, $pipes]) {
            $output = stream_get_contents($pipes[1]);
            $errors = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $this->assertSame(0, proc_close($process), "racer failed (a PostgreSQL 'too many clients' error needs a retry):
{$output}
{$errors}");
            $this->assertSame(1, preg_match('/^'.ParallelLoginRacerTest::RESULT_PREFIX.'(.+)$/m', $errors, $match), "racer printed no result:
{$output}
{$errors}");
            $result = json_decode($match[1], true, flags: JSON_THROW_ON_ERROR);
            $outcomes[match (true) {
                $result['submits'] === 1 => 'sent',
                ($result['errors']['login'] ?? null) === LoginAttempt::Busy->message() => 'busy',
                ($result['errors']['code'] ?? null) === CodeStatus::Locked->message() => 'locked',
                default => $this->fail('unexpected racer outcome: '.$match[1]),
            }]++;
        }

        $this->assertSame($racers, array_sum($outcomes));
        $this->assertGreaterThanOrEqual(1, $outcomes['sent']);
        $this->assertLessThanOrEqual(5, $outcomes['sent'], 'credential submissions for one code: '.json_encode($outcomes));
        $failed = (int) $this->owner()->query("select failed_logins from register_codes where code_hash = decode('".bin2hex($codeHash)."', 'hex')")->fetchColumn();
        $this->assertSame($outcomes['sent'], $failed, 'every submission was counted');

        $this->assertSame(5 - $outcomes['sent'], $this->drainSlots($this->store(), $codeHash), 'no reservation was left behind');
    }

    public function test_an_operator_revoked_account_is_never_reattached(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $revoked = $original[0]->accountId;
        $this->expire([$revoked]);
        $this->owner()->exec("update accounts set status = 'revoked' where id = ".$this->owner()->quote($revoked));

        $code = $this->addCode('code-two-0123456789');
        $this->assertRejected(RejectionReason::AccountAlreadyRegistered, fn () => $registrar->register($code, 'https://hooks.example.com/a', $session,
            self::account('1111111111'), '198.51.100.1'));
        $this->assertRejected(RejectionReason::UserAlreadyRegistered, fn () => $registrar->register($code, 'https://hooks.example.com/a', $session,
            self::account('2222222222'), '198.51.100.1'), 'a revoked account still binds its user');
        $this->assertSame('revoked', $this->owner()->query('select status from accounts where id = '.$this->owner()->quote($revoked))->fetchColumn());
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code));
    }

    public function test_reattaching_onto_a_disabled_endpoint_is_refused(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->owner()->exec("update webhook_endpoints set status = 'disabled', disabled_at = now()");
        $this->expire([$original[0]->accountId]);

        $code = $this->addCode('code-two-0123456789');
        $this->assertRejected(RejectionReason::EndpointDisabled, fn () => $registrar->register($code, 'https://hooks.example.com/b', $session,
            self::account('1111111111'), '198.51.100.1'));
        $this->assertSame(['disabled', 'https://hooks.example.com/a'], array_values($this->owner()->query('select status, url from webhook_endpoints')->fetch()));
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code));
    }

    /**
     * New registrations always get their own endpoint, so only an endpoint
     * shared from before the one-account rule (simulated here by moving a
     * connection onto it) can have another active account.
     */
    public function test_the_url_cannot_change_while_another_active_account_uses_the_endpoint(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $sibling = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'USER-2', 'ORG-1', 'C'),
            self::account('2222222222'), '198.51.100.1');
        $owner = $this->owner();
        $endpointOf = fn (string $accountId) => 'select c.endpoint_id from accounts a join connections c on c.id = a.connection_id where a.id = '.$owner->quote($accountId);
        $owner->exec('update connections set endpoint_id = ('.$endpointOf($original[0]->accountId).') where id = (select connection_id from accounts where id = '.$owner->quote($sibling[0]->accountId).')');
        $owner->exec('delete from webhook_endpoints w where not exists (select 1 from connections c where c.endpoint_id = w.id)');
        $this->expire([$original[0]->accountId]);

        $code = $this->addCode('code-three-0123456789');
        $this->assertRejected(RejectionReason::EndpointUrlLocked, fn () => $registrar->register($code, 'https://hooks.example.com/new', $session,
            self::account('1111111111'), '198.51.100.1'));
        $this->assertSame(['https://hooks.example.com/a'], $owner->query('select url from webhook_endpoints')->fetchAll(PDO::FETCH_COLUMN));
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code));

        $same = $registrar->register($code, 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->assertTrue($same[0]->reattached, 'the unchanged URL is accepted');
    }

    public function test_every_test_runs_under_its_own_bank_roles(): void
    {
        $this->assertMatchesRegularExpression('/^test[0-9a-f]{12}$/', $this->bank);
        $groups = $this->owner()->query(
            'select g.rolname from pg_auth_members m join pg_roles g on g.oid = m.roleid join pg_roles u on u.oid = m.member where u.rolname = '.$this->owner()->quote($this->role),
        )->fetchAll(PDO::FETCH_COLUMN);
        $this->assertContains("wrapbiz_{$this->bank}_registration", $groups);
        $this->assertSame([], array_values(array_filter($groups, fn (string $group) => str_starts_with($group, 'wrapbiz_kbank_'))));
        $this->assertSame($this->bank, $this->owner()->query('select wrapbiz_bank()')->fetchColumn());
    }

    public function test_register_connection_returns_the_catch_up_window_baked_into_the_database(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);

        $again = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');

        $this->assertSame([self::CATCHUP_DAYS, self::CATCHUP_DAYS], [$original[0]->catchUpDays, $again[0]->catchUpDays]);
    }

    private function skipWithoutAuditedLimit(): void
    {
        if ($this->owner()->query("select to_regprocedure('public.wrapbiz_audited_catchup_days()') is null")->fetchColumn()) {
            $this->markTestSkipped('the wrapbiz migrations predate the audited catch-up limit (migration 3, round 27)');
        }
    }

    /**
     * wrapbiz round 27 (FIN-2601): register_connection returns the audited
     * limit the worker's claims use, not wrapbiz_catchup_days(), which a hand
     * edit changes without its audit row.
     */
    public function test_register_connection_returns_the_audited_limit_not_a_hand_edit(): void
    {
        $this->skipWithoutAuditedLimit();
        $this->owner()->exec("create or replace function wrapbiz_catchup_days() returns integer language sql stable parallel safe
            set search_path = public, pg_temp as 'select 2::integer'");
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');

        $result = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');

        $this->assertSame(self::CATCHUP_DAYS, $result[0]->catchUpDays);
    }

    /**
     * wrapbiz round 27 (FIN-2601): without an audited limit (here a malformed
     * latest catchup_days.changed row) register_connection returns NULL, and a
     * reattached account gets the warning instead of a missed range.
     */
    public function test_no_audited_limit_shows_the_warning_instead_of_a_range(): void
    {
        $this->skipWithoutAuditedLimit();
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);
        $this->owner()->exec("update accounts set last_success_at = '2026-09-30T10:15:00Z'");
        $this->owner()->exec("insert into audit_log (actor, action, detail) values ('migrate', 'catchup_days.changed', '{\"to\": \"x\"}')");

        $again = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1')[0];

        $this->assertTrue($again->reattached);
        $this->assertNull($again->catchUpDays);
        $this->assertNull($again->missed);
        $this->assertTrue($again->missedUnknown);
        $this->assertSame('2026-09-30 17:15', $again->disconnectedSince?->format('Y-m-d H:i'));
    }

    public function test_account_states_classify_every_listed_account(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $user = fn (int $i) => new BankSession('t', "USER-{$i}", 'ORG-1', 'C');
        $register = fn (int $i, string $number) => $registrar->register($this->addCode("code-{$i}-0123456789"), 'https://hooks.example.com/a', $user($i),
            self::account($number), '198.51.100.1')[0]->accountId;
        $active = $register(1, '1111111111');
        $expired = $register(2, '2222222222');
        $paused = $register(3, '3333333333');
        $mismatch = $register(4, '4444444444');
        $this->expire([$expired, $paused, $mismatch]);
        $owner = $this->owner();
        $owner->exec("update accounts set status = 'paused' where id = ".$owner->quote($paused));
        $owner->prepare("insert into quarantined_rows (account_id, reason, raw, row_hash) values (?, 'fingerprint_mismatch', '{}', decode(?, 'hex'))")
            ->execute([$mismatch, str_repeat('ab', 32)]);

        $accounts = [
            'active' => self::account('1111111111'),
            'expired' => self::account('2222222222'),
            'paused' => self::account('3333333333'),
            'mismatch' => self::account('4444444444'),
            'unknown' => self::account('5555555555'),
        ];
        $code = $this->addCode('code-list-0123456789');
        $bound = fn (string $own, AccountState $state) => [
            ...array_fill_keys(array_keys($accounts), AccountState::UserBound),
            $own => $state,
        ];

        $this->assertSame([
            'active' => AccountState::Registered,
            'expired' => AccountState::Registered,
            'paused' => AccountState::Held,
            'mismatch' => AccountState::Held,
            'unknown' => AccountState::New,
        ], $registrar->accountStates($code, $user(9), $accounts), 'a K BIZ user with no account yet');
        $this->assertSame($bound('expired', AccountState::Reattachable), $registrar->accountStates($code, $user(2), $accounts));
        $this->assertSame($bound('active', AccountState::Registered), $registrar->accountStates($code, $user(1), $accounts));
        $this->assertSame($bound('paused', AccountState::Held), $registrar->accountStates($code, $user(3), $accounts));
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code), 'asking never consumes the code');

        $this->assertRejected(RejectionReason::UserAlreadyRegistered, fn () => $registrar->register($code, 'https://hooks.example.com/a', $user(2), $accounts['unknown'], '198.51.100.1'));
        $this->assertRejected(RejectionReason::AccountAlreadyRegistered, fn () => $registrar->register($code, 'https://hooks.example.com/a', $user(9), $accounts['paused'], '198.51.100.1'));
        $this->assertTrue($registrar->register($code, 'https://hooks.example.com/a', $user(2), $accounts['expired'], '198.51.100.1')[0]->reattached);
    }

    /**
     * The README's procedure for releasing a held account: `wrapbiz-kbank op
     * unpause` calls operator_unpause_account() as a member of the operator
     * group role, which is what this test does too.
     */
    public function test_the_readme_procedure_releases_a_held_account_for_a_re_login(): void
    {
        $readme = (string) file_get_contents(base_path('README.md'));
        $section = substr($readme, (int) strpos($readme, '### Releasing a held (paused) account'));
        $this->assertStringContainsString('wrapbiz-kbank op unpause', $section);
        $this->assertStringNotContainsString('update accounts', $section, 'operators never edit the database by hand');

        $registrar = $this->app->make(Registrar::class);
        $user = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $user,
            self::account('1111111111'), '198.51.100.1');
        $accountId = $original[0]->accountId;
        $owner = $this->owner();
        $quoted = $owner->quote($accountId);
        // What the poller leaves behind: the account paused with an open
        // mismatch, and (it was the last active one) the connection revoked
        // with its credential wiped.
        $owner->exec("update accounts set status = 'paused' where id = {$quoted}");
        $owner->prepare("insert into quarantined_rows (account_id, reason, raw, row_hash) values (?, 'fingerprint_mismatch', '{}', decode(?, 'hex'))")
            ->execute([$accountId, str_repeat('cd', 32)]);
        $owner->exec("update connections set status = 'revoked', revoked_reason = 'all_accounts_held', credential_format = null, credential_key_id = null,
                             credential_nonce = null, credential_ciphertext = null
                       where id = (select connection_id from accounts where id = {$quoted})");
        $states = fn (BankSession $session, string $code) => $registrar->accountStates($code, $session, ['it' => self::account('1111111111')])['it'];
        $code = $this->addCode('code-two-0123456789');
        $this->assertSame(AccountState::Held, $states($user, $code));

        [$operator, $login] = $this->operator();
        $operator->prepare('select operator_unpause_account(?::uuid)')->execute([$accountId]);
        $this->assertGreaterThanOrEqual(1, (int) $owner->query("select count(*) from audit_log where actor = 'operator:{$login}'")->fetchColumn(), 'the actor is the operator login');

        $this->assertSame(0, (int) $owner->query("select count(*) from quarantined_rows where account_id = {$quoted} and status = 'open'")->fetchColumn());
        $this->assertSame(AccountState::Reattachable, $states($user, $code));
        $this->assertSame(AccountState::Registered, $states(new BankSession('t', 'USER-2', 'ORG-1', 'C'), $code), 'only the same K BIZ user');
        $again = $registrar->register($code, 'https://hooks.example.com/a', $user, self::account('1111111111'), '198.51.100.1');
        $this->assertTrue($again[0]->reattached);
        $this->assertSame($accountId, $again[0]->accountId);
        $this->assertSame('active', $owner->query("select status from accounts where id = {$quoted}")->fetchColumn());
    }

    /**
     * The README's handover: after op release-account, a different K BIZ user
     * of the same organisation takes the account over. It keeps its id, starts
     * fresh on a new endpoint, and the undelivered range comes back as a gap.
     */
    public function test_a_released_account_is_handed_over_with_a_gap_and_a_fresh_endpoint(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $first = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $colleague = new BankSession('t', 'USER-2', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $first, self::account('1111111111'), '198.51.100.1');
        $accountId = $original[0]->accountId;
        $code = $this->addCode('code-two-0123456789');
        $this->assertSame(AccountState::Registered, $registrar->accountStates($code, $colleague, ['it' => self::account('1111111111')])['it']);

        [$operator] = $this->operator();
        $operator->prepare('select operator_release_account(?::uuid, ?)')->execute([$accountId, 'the first user left']);

        $this->assertSame(AccountState::Reattachable, $registrar->accountStates($code, $colleague, ['it' => self::account('1111111111')])['it']);
        $this->assertSame(AccountState::Registered, $registrar->accountStates($code, new BankSession('t', 'USER-1', 'ORG-2', 'C'), ['it' => self::account('1111111111')])['it'], 'another organisation cannot');
        $handedOver = $registrar->register($code, 'https://hooks.example.com/b', $colleague, self::account('1111111111'), '198.51.100.1')[0];

        $this->assertSame($accountId, $handedOver->accountId);
        $this->assertTrue($handedOver->handover);
        $this->assertNotNull($handedOver->handoverGap, 'the range that may not have been delivered is reported');
        $this->assertTrue($handedOver->handoverGap->from->lessThan($handedOver->handoverGap->to));
        $this->assertSame(0, $handedOver->handoverGap->deliveredCount, 'nothing was delivered for this account yet');
        $this->assertSame(0, $handedOver->handoverGap->pendingCount);
        $this->assertNull($handedOver->missed, 'no catch-up range for a hand-over');
        $urls = $this->owner()->query('select url from webhook_endpoints order by created_at')->fetchAll(PDO::FETCH_COLUMN);
        $this->assertSame(['https://hooks.example.com/a', 'https://hooks.example.com/b'], $urls, 'a fresh endpoint; the old one keeps its URL');
    }

    /** BUG-R8-02: a hand-over whose range is empty is still a hand-over. */
    public function test_an_empty_gap_hand_over_is_still_a_hand_over(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'USER-1', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1');
        $accountId = $original[0]->accountId;
        [$operator] = $this->operator();
        $operator->prepare('select operator_release_account(?::uuid, ?)')->execute([$accountId, 'the first user left']);
        // The previous user had swept and polled everything up to now, so
        // nothing before the hand-over can be missing.
        $this->owner()->exec("update accounts set last_swept_day = (now() at time zone 'Asia/Bangkok')::date, last_success_at = now() where id = ".$this->owner()->quote($accountId));

        $handedOver = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/b', new BankSession('t', 'USER-2', 'ORG-1', 'C'),
            self::account('1111111111'), '198.51.100.1')[0];

        $this->assertSame($accountId, $handedOver->accountId);
        $this->assertTrue($handedOver->handover);
        $this->assertNull($handedOver->handoverGap);
        $this->assertNull($handedOver->missed, 'never a catch-up range for a hand-over');
        $this->assertSame(2, (int) $this->owner()->query('select count(*) from webhook_endpoints')->fetchColumn(), 'still a fresh endpoint');
    }

    public function test_a_same_user_re_login_reports_no_handover_gap(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $session = new BankSession('t', 'USER-1', 'ORG-1', 'C');
        $original = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1');
        $this->expire([$original[0]->accountId]);

        $again = $registrar->register($this->addCode('code-two-0123456789'), 'https://hooks.example.com/a', $session, self::account('1111111111'), '198.51.100.1')[0];

        $this->assertTrue($again->reattached);
        $this->assertFalse($again->handover);
        $this->assertNull($again->handoverGap);
    }

    /**
     * A personal login in this bank's operator group role, as `wrapbiz-kbank op` uses.
     *
     * @return array{PDO, string} the connection and its login name
     */
    private function operator(): array
    {
        $login = 'wrapbiz_op_test_'.bin2hex(random_bytes(6));
        $password = bin2hex(random_bytes(16));
        $this->extraLogins[] = $login;
        $this->owner()->exec("create role {$login} login password '{$password}' in role wrapbiz_{$this->bank}_operator");

        return [new PDO($this->scratchDsn, $login, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]), $login];
    }

    private function auditRows(): int
    {
        return (int) $this->owner()->query('select count(*) from audit_log')->fetchColumn();
    }

    /**
     * Spends the code's state budget the way a customer would: ten views of
     * the same one-account list.
     */
    private function spendStatesBudget(string $codeHash, ?string $userFingerprint = null, ?string $fingerprint = null): void
    {
        $userFingerprint ??= random_bytes(32);
        $fingerprint ??= random_bytes(32);
        for ($i = 0; $i < 10; $i++) {
            $this->store()->accountStates($codeHash, random_bytes(32), $userFingerprint, [$fingerprint]);
        }
    }

    public function test_account_states_answer_ten_calls_per_code_and_audit_each(): void
    {
        $store = $this->store();
        $code = $this->addCode('code-calls-0123456789');
        $fingerprint = random_bytes(32);
        $org = random_bytes(32);
        $user = random_bytes(32);

        for ($i = 1; $i <= 10; $i++) {
            $this->assertSame(CodeStatus::Usable, $store->codeStatus($code), "before call {$i}");
            $before = $this->auditRows();
            $store->accountStates($code, $org, $user, [$fingerprint]);
            $this->assertSame($before + 1, $this->auditRows(), "call {$i} writes one audit row");
        }

        $this->assertSame(CodeStatus::Exhausted, $store->codeStatus($code));
        $this->assertSame(LoginAttempt::Exhausted, $store->beginLoginAttempt($code)->attempt);
        $this->assertRejected(RejectionReason::StatesBudgetExhausted, fn () => $store->accountStates($code, $org, $user, [$fingerprint]));
        $this->assertCount(1, $store->accountStates($this->addCode('code-other-0123456789'), $org, $user, [$fingerprint]), 'the budget is per code');
    }

    public function test_a_call_that_would_pass_fifty_distinct_accounts_is_refused_by_name(): void
    {
        $code = $this->addCode('code-distinct-0123456789');
        $org = random_bytes(32);
        $user = random_bytes(32);

        $this->assertCount(45, $this->store()->accountStates($code, $org, $user, array_map(fn () => random_bytes(32), range(1, 45))));
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code));

        $before = $this->auditRows();
        $this->assertRejected(RejectionReason::StatesBudgetExhausted, fn () => $this->store()->accountStates($code, $org, $user, array_map(fn () => random_bytes(32), range(1, 6))));
        $this->assertSame(CodeStatus::Exhausted, $this->store()->codeStatus($code), 'the refusal is committed (BUG-R6-01)');
        $this->assertSame(LoginAttempt::Exhausted, $this->store()->beginLoginAttempt($code)->attempt);
        $this->assertSame($before + 1, $this->auditRows(), 'the refusal is audited');
    }

    public function test_fifty_distinct_accounts_exhaust_the_code_for_new_logins(): void
    {
        $code = $this->addCode('code-fifty-0123456789');
        $org = random_bytes(32);
        $user = random_bytes(32);
        $first = array_map(fn () => random_bytes(32), range(1, 30));
        $second = array_map(fn () => random_bytes(32), range(1, 20));

        $this->assertCount(30, $this->store()->accountStates($code, $org, $user, $first));
        $this->assertCount(20, $this->store()->accountStates($code, $org, $user, $second));

        $this->assertSame(CodeStatus::Exhausted, $this->store()->codeStatus($code));
        $this->assertSame(LoginAttempt::Exhausted, $this->store()->beginLoginAttempt($code)->attempt);
    }

    /**
     * The budget bounds lookups and stops new bank logins; a customer whose
     * list was already answered must still be able to register from it.
     */
    public function test_a_login_whose_tenth_states_call_succeeded_can_still_register(): void
    {
        $code = $this->addCode('code-tenth-0123456789');
        $user = random_bytes(32);
        $fingerprint = random_bytes(32);
        $this->spendStatesBudget($code, $user, $fingerprint);

        $created = $this->store()->register($this->registration($code, [$fingerprint], random_bytes(32), userFingerprint: $user));

        $this->assertCount(1, $created);
        $this->assertSame(CodeStatus::Used, $this->store()->codeStatus($code));
    }

    public function test_a_list_of_fifty_accounts_can_still_register_one_of_them(): void
    {
        $code = $this->addCode('code-fifty-reg-0123456789');
        $user = random_bytes(32);
        $fingerprints = array_map(fn () => random_bytes(32), range(1, 50));
        $this->store()->accountStates($code, random_bytes(32), $user, $fingerprints);

        $this->assertCount(1, $this->store()->register($this->registration($code, [$fingerprints[7]], random_bytes(32), userFingerprint: $user)));
    }

    public function test_an_exhausted_code_is_refused_before_any_bank_call(): void
    {
        $code = 'code-page-0123456789';
        $this->spendStatesBudget($this->addCode($code));
        $bank = FakeBank::fake();

        $this->from('/')->post('/code', ['code' => $code])->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่']);

        $this->assertCount(0, $bank->recorded());
    }

    /** BUG-R6-01: 49 accounts asked about, then a list with 2 new ones. */
    public function test_a_refused_list_exhausts_the_code_before_the_next_bank_login(): void
    {
        $code = 'code-r601-0123456789';
        $codeHash = $this->addCode($code);
        $this->store()->accountStates($codeHash, random_bytes(32), random_bytes(32), array_map(fn () => random_bytes(32), range(1, 49)));
        $bank = FakeBank::fake();

        $this->post('/code', ['code' => $code])->assertRedirect('/login');
        $this->post('/login', ['username' => 'u', 'password' => 'p', 'webhook_url' => 'https://hooks.example.com/a'])->assertRedirect('/approve');
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->get('/accounts')->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่']);
        $bankRequests = count($bank->recorded());

        $this->from('/')->post('/code', ['code' => $code])->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่']);
        $this->assertCount($bankRequests, $bank->recorded(), 'no bank request with the exhausted code');
        $this->assertSame(CodeStatus::Exhausted, $this->store()->codeStatus($codeHash));
    }

    public function test_a_code_exhausted_after_it_was_accepted_is_refused_at_login_before_any_bank_call(): void
    {
        $code = 'code-login-0123456789';
        $codeHash = $this->addCode($code);
        $bank = FakeBank::fake();
        $this->post('/code', ['code' => $code])->assertRedirect('/login');
        $this->spendStatesBudget($codeHash);

        $this->post('/login', ['username' => 'u', 'password' => 'p', 'webhook_url' => 'https://hooks.example.com/a'])
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่']);

        $this->assertCount(0, $bank->recorded());
    }

    public function test_the_registration_session_has_the_time_limits_after_every_connect(): void
    {
        $owner = $this->owner();
        $owner->exec("alter role {$this->role} set default_transaction_isolation = 'serializable'");
        $limits = fn () => (array) DB::connection('wrapbiz')->selectOne(
            "select current_setting('statement_timeout') as statement_timeout, current_setting('lock_timeout') as lock_timeout,
                    current_setting('transaction_isolation') as transaction_isolation",
        );
        $expected = ['statement_timeout' => '15s', 'lock_timeout' => '5s', 'transaction_isolation' => 'read committed'];

        $this->assertSame($expected, $limits(), 'READ COMMITTED even when the role default says otherwise');
        DB::reconnect('wrapbiz');
        $this->assertSame($expected, $limits());
        DB::purge('wrapbiz');
        $this->assertSame($expected, $limits());
    }

    public function test_a_held_lock_fails_the_call_after_the_lock_timeout(): void
    {
        $code = $this->addCode('code-locked-0123456789');
        $this->assertSame(CodeStatus::Usable, $this->store()->codeStatus($code));
        $owner = $this->owner();
        $owner->beginTransaction();
        $owner->exec('lock table register_codes in access exclusive mode');

        $started = microtime(true);
        try {
            $this->store()->codeStatus($code);
            $this->fail('expected the lock timeout');
        } catch (RegistrationStoreUnavailable $exception) {
            $this->assertSame('55P03', $exception->sqlState);
        } finally {
            $owner->rollBack();
        }
        $this->assertEqualsWithDelta(5.0, microtime(true) - $started, 2.0);
    }

    public function test_account_states_need_a_usable_code(): void
    {
        $code = $this->addCode('code-used-0123456789');
        $this->store()->register($this->registration($code, [random_bytes(32)], random_bytes(32)));

        $this->assertRejected(RejectionReason::CodeUnusable, fn () => $this->store()->accountStates($code, random_bytes(32), random_bytes(32), [random_bytes(32)]));
        $this->assertRejected(RejectionReason::CodeUnusable, fn () => $this->store()->accountStates(hash('sha256', 'never-issued', true), random_bytes(32), random_bytes(32), [random_bytes(32)]));
    }

    public function test_the_http_flow_shows_held_accounts_disabled_and_refuses_them(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $held = $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', new BankSession('t', 'ANOTHER-USER', 'ORG-9', 'C'),
            self::account('1234567890'), '198.51.100.1');
        $this->owner()->exec("update accounts set status = 'paused' where id = ".$this->owner()->quote($held[0]->accountId));

        $this->addCode('code-http-0123456789');
        $this->reachAccountSelection('code-http-0123456789');
        $html = (string) $this->get('/accounts')->assertOk()->getContent();
        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-0"[^>]*disabled/s', $html);
        $this->assertStringContainsString('บัญชีนี้ถูกระงับ ติดต่อผู้ดูแล', $html);

        $tokens = array_column(session('registration.accounts'), 'token');
        $this->from('/accounts')->post('/accounts', ['list' => session('registration.list_nonce'), 'account' => $tokens[0]])
            ->assertRedirect('/accounts')
            ->assertSessionHasErrors(['account' => 'บัญชีนี้ถูกระงับ ติดต่อผู้ดูแล']);
        $this->assertSame(1, (int) $this->owner()->query('select count(*) from connections')->fetchColumn());

        $this->post('/accounts', ['list' => session('registration.list_nonce'), 'account' => $tokens[1]])->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_the_http_flow_shows_the_other_accounts_of_a_bound_user_disabled(): void
    {
        $registrar = $this->app->make(Registrar::class);
        $listedByTheFakeBank = new BankSession('session-token-xyz', 'U-1', 'ORG-9', 'C');
        $registrar->register($this->addCode('code-one-0123456789'), 'https://hooks.example.com/a', $listedByTheFakeBank, self::account('1234567890'), '198.51.100.1');

        $this->addCode('code-http-0123456789');
        $this->reachAccountSelection('code-http-0123456789');
        $html = (string) $this->get('/accounts')->assertOk()->getContent();

        $userBound = 'ผู้ใช้ KBiz นี้ลงทะเบียนบัญชีอื่นไว้แล้ว — ถ้าต้องการเพิ่มบัญชี กรุณาสร้างผู้ใช้ KBiz ใหม่';
        $this->assertStringContainsString('<p class="hint" id="account-1-note">'.$userBound.'</p>', $html);
        $this->assertStringContainsString('<p class="hint" id="account-0-note">บัญชีนี้ลงทะเบียนแล้ว ติดต่อผู้ดูแล</p>', $html);
        $this->assertStringNotContainsString('id="accounts-submit"', $html);
        $tokens = array_column(session('registration.accounts'), 'token');
        $this->from('/accounts')->post('/accounts', ['list' => session('registration.list_nonce'), 'account' => $tokens[1]])
            ->assertSessionHasErrors(['account' => $userBound]);
        $this->assertSame(1, (int) $this->owner()->query('select count(*) from connections')->fetchColumn());
    }

    public function test_the_reservation_lifetime_matches_what_the_login_timeout_is_bounded_by(): void
    {
        $code = $this->addCode('code-ttl-0123456789');
        $this->reserve($this->store(), $code);

        $seconds = (float) $this->owner()->query('select extract(epoch from expires_at - now()) from register_code_reservations')->fetchColumn();

        $this->assertEqualsWithDelta(AttemptReservation::TTL_SECONDS, $seconds, 5.0);
    }

    private function reachAccountSelection(string $code): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => $code])->assertRedirect('/login');
        $this->post('/login', ['username' => 'u', 'password' => 'p', 'webhook_url' => 'https://hooks.example.com/a'])->assertRedirect('/approve');
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->get('/accounts')->assertOk();
    }

    private function reserve(PostgresRegistrationStore $store, string $codeHash): string
    {
        $reservation = $store->beginLoginAttempt($codeHash);
        $this->assertSame(LoginAttempt::Reserved, $reservation->attempt);

        return (string) $reservation->reservationId;
    }

    /**
     * @return int how many attempts could still be reserved (they stay reserved)
     */
    private function drainSlots(PostgresRegistrationStore $store, string $codeHash): int
    {
        $granted = 0;
        while ($granted < 10 && $store->beginLoginAttempt($codeHash)->attempt === LoginAttempt::Reserved) {
            $granted++;
        }

        return $granted;
    }

    private static function account(string $digits): BankAccount
    {
        return new BankAccount(AccountNumber::tryFrom($digits), 'SA');
    }
}
