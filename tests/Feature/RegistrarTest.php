<?php

namespace Tests\Feature;

use App\Kbiz\BankAccount;
use App\Kbiz\BankSession;
use App\Registration\Registrar;
use App\Registration\RegistrationResult;
use App\Security\AccountNumber;
use App\Wrapbiz\AccountState;
use App\Wrapbiz\AttemptReservation;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\NewRegistration;
use App\Wrapbiz\RegisteredAccount;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

final class RegistrarTest extends TestCase
{
    /** @var list<NewRegistration> */
    private array $sent = [];

    /** @var list<array{code: string, org: string, user: string, fingerprints: list<string>}> */
    private array $stateQueries = [];

    /**
     * @param  callable(NewRegistration): list<RegisteredAccount>  $respond
     * @param  ?callable(list<string>): array<string, AccountState>  $states
     */
    private function registrarReturning(callable $respond, ?callable $states = null): Registrar
    {
        $states ??= fn (array $fingerprints) => array_fill_keys($fingerprints, AccountState::New);
        $this->app->instance(RegistrationStore::class, new class($respond, $states, $this->sent, $this->stateQueries) implements RegistrationStore
        {
            /**
             * @param  list<NewRegistration>  $sent
             * @param  list<array{code: string, org: string, user: string, fingerprints: list<string>}>  $stateQueries
             */
            public function __construct(private $respond, private $states, private array &$sent, private array &$stateQueries) {}

            public function accountStates(string $codeHash, string $orgFingerprint, string $userFingerprint, array $fingerprints): array
            {
                $this->stateQueries[] = ['code' => $codeHash, 'org' => $orgFingerprint, 'user' => $userFingerprint, 'fingerprints' => $fingerprints];

                return ($this->states)($fingerprints);
            }

            public function codeStatus(string $codeHash): CodeStatus
            {
                return CodeStatus::Usable;
            }

            public function beginLoginAttempt(string $codeHash): AttemptReservation
            {
                return AttemptReservation::refused(LoginAttempt::Busy);
            }

            public function endLoginAttempt(string $codeHash, string $reservationId): void {}

            public function recordFailedLogin(string $codeHash, ?string $reservationId): bool
            {
                return false;
            }

            public function register(NewRegistration $registration): array
            {
                $this->sent[] = $registration;

                return ($this->respond)($registration);
            }
        });

        return $this->app->make(Registrar::class);
    }

    /**
     * @return non-empty-list<BankAccount>
     */
    private static function accounts(): array
    {
        return array_map(
            fn (string $digits) => new BankAccount(AccountNumber::tryFrom($digits), 'SA'),
            ['1111111111', '2222222222', '3333333333'],
        );
    }

    private function register(Registrar $registrar): array
    {
        return $registrar->register(str_repeat("\x01", 32), 'https://hooks.example.com/x', new BankSession('t', 'u', 'ORG', 'c'), self::accounts()[0], '198.51.100.1');
    }

    public function test_exactly_one_account_is_sent(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => [new RegisteredAccount($r->accounts[0]->id, false)]);

        $results = $this->register($registrar);

        $sent = $this->sent[0]->accounts;
        $this->assertCount(1, $sent);
        $this->assertSame('xxx-x-x1111-x', $sent[0]->masked);
        $this->assertSame([$sent[0]->id], array_map(fn ($r) => $r->accountId, $results));
        $this->assertSame(['xxx-x-x1111-x'], array_map(fn ($r) => $r->maskedNumber, $results));
        $this->assertFalse($results[0]->reattached);
    }

    public function test_a_reattached_row_shows_its_existing_id_with_the_number_that_was_sent(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => [new RegisteredAccount('existing-a', true)]);

        $results = $this->register($registrar);

        $this->assertSame('existing-a', $results[0]->accountId);
        $this->assertSame('xxx-x-x1111-x', $results[0]->maskedNumber);
        $this->assertTrue($results[0]->reattached);
    }

    public function test_rows_that_do_not_match_the_request_never_guess_a_number(): void
    {
        $logged = [];
        Log::listen(function ($message) use (&$logged) {
            $logged[] = $message->message;
        });
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => [
            new RegisteredAccount('existing-a', true),
            new RegisteredAccount($r->accounts[0]->id, false),
        ]);

        $results = $this->register($registrar);

        $this->assertSame([null, 'xxx-x-x1111-x'], array_map(fn ($r) => $r->maskedNumber, $results));
        $this->assertContains('register_connection rows did not line up with the request', $logged);
    }

    public function test_a_new_row_with_an_unexpected_id_gets_no_number(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => [new RegisteredAccount('someone-else', false)]);

        $results = $this->register($registrar);

        $this->assertCount(1, $results);
        $this->assertNull($results[0]->maskedNumber);
    }

    public function test_fingerprints_bind_the_registration_to_the_organisation_and_the_bank_user(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => array_map(fn ($a) => new RegisteredAccount($a->id, false), $r->accounts));

        $this->register($registrar);
        $sent = $this->sent[0];

        $key = (string) base64_decode((string) config('wrapbiz.fingerprint_key'), true);
        $this->assertSame(hash_hmac('sha256', 'kbank:org:ORG', $key, true), $sent->orgFingerprint);
        $this->assertSame(hash_hmac('sha256', 'kbank:user:u', $key, true), $sent->userFingerprint);
        $this->assertNotSame($sent->orgFingerprint, $sent->userFingerprint);
    }

    /**
     * @param  callable(NewRegistration): RegisteredAccount  $row
     */
    private function registerReturningRow(callable $row): RegistrationResult
    {
        return $this->register($this->registrarReturning(fn (NewRegistration $r) => [$row($r)]))[0];
    }

    public function test_only_a_reattached_row_gets_a_missed_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $old = new \DateTimeImmutable('2026-09-01T00:00:00Z');

        $reattached = $this->registerReturningRow(fn () => new RegisteredAccount('existing-a', true, $old, catchUpDays: 7));
        $new = $this->registerReturningRow(fn (NewRegistration $r) => new RegisteredAccount($r->accounts[0]->id, false, $old, catchUpDays: 7));
        $neverPolled = $this->registerReturningRow(fn () => new RegisteredAccount('existing-c', true, null, catchUpDays: 7));

        $this->assertSame('2026-09-01 07:00', $reattached->missed?->from->format('Y-m-d H:i'));
        $this->assertSame('2026-10-07', $reattached->missed?->lastMissedDay->format('Y-m-d'));
        $this->assertNull($new->missed);
        $this->assertNull($neverPolled->missed);
        $this->assertSame([7, 7, 7], [$reattached->catchUpDays, $new->catchUpDays, $neverPolled->catchUpDays]);
    }

    public function test_a_hand_over_reports_its_gap_in_bangkok_time_and_no_catch_up_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $old = new \DateTimeImmutable('2026-09-01T00:00:00Z');

        $result = $this->registerReturningRow(fn () => new RegisteredAccount('taken-over', true, $old, catchUpDays: 7, handover: true,
            gapFrom: new \DateTimeImmutable('2026-10-01T03:04:05Z'), gapTo: new \DateTimeImmutable('2026-10-16T01:55:00Z'), gapDeliveredCount: 4, gapPendingCount: 1));

        $this->assertTrue($result->handover);
        $this->assertNull($result->missed);
        $this->assertSame('2026-10-01 10:04:05 +07:00', $result->handoverGap?->from->format('Y-m-d H:i:s P'));
        $this->assertSame('2026-10-16 08:55:00 +07:00', $result->handoverGap?->to->format('Y-m-d H:i:s P'));
        $this->assertSame(4, $result->handoverGap?->deliveredCount);
        $this->assertSame(1, $result->handoverGap?->pendingCount);
    }

    public function test_an_empty_gap_hand_over_has_no_gap_and_no_catch_up_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));

        $result = $this->registerReturningRow(fn () => new RegisteredAccount('taken-over', true, new \DateTimeImmutable('2026-09-01T00:00:00Z'), catchUpDays: 7, handover: true));

        $this->assertTrue($result->handover);
        $this->assertNull($result->handoverGap);
        $this->assertNull($result->missed);
    }

    public function test_a_same_user_re_login_is_not_a_hand_over(): void
    {
        $result = $this->registerReturningRow(fn () => new RegisteredAccount('same-user', true, new \DateTimeImmutable('2026-09-01T00:00:00Z'), catchUpDays: 7));

        $this->assertFalse($result->handover);
        $this->assertNull($result->handoverGap);
    }

    public function test_the_missed_range_uses_the_catch_up_days_the_database_returned(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $tenDaysAgo = new \DateTimeImmutable('2026-10-06T10:00:00+07:00');

        $within = $this->registerReturningRow(fn () => new RegisteredAccount('within-14', true, $tenDaysAgo, catchUpDays: 14));
        $beyond = $this->registerReturningRow(fn () => new RegisteredAccount('beyond-3', true, $tenDaysAgo, catchUpDays: 3));
        $unreadable = $this->registerReturningRow(fn () => new RegisteredAccount('unreadable', true, $tenDaysAgo, catchUpDays: null));

        $this->assertNull($within->missed);
        $this->assertSame('2026-10-11', $beyond->missed?->lastMissedDay->format('Y-m-d'));
        $this->assertNull($unreadable->missed, 'an unreadable window never throws after the commit');
        $this->assertNull($unreadable->catchUpDays);
        $this->assertTrue($unreadable->missedUnknown);
        $this->assertFalse($within->missedUnknown || $beyond->missedUnknown);
    }

    /**
     * wrapbiz round 27 (FIN-2601): register_connection returns the audited
     * catch-up limit, NULL when the database has none. A reattached account
     * then gets a warning that its missed range cannot be told, with the
     * time its fetch starts from, and no range from a guessed window; a new
     * account and a hand-over (no catch-up) get neither.
     */
    public function test_no_catch_up_window_warns_instead_of_a_missed_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $old = new \DateTimeImmutable('2026-09-01T00:00:00Z');

        $reattached = $this->registerReturningRow(fn () => new RegisteredAccount('existing-a', true, $old, catchUpDays: null));
        $neverPolled = $this->registerReturningRow(fn () => new RegisteredAccount('existing-b', true, null, null, catchUpDays: null));
        $new = $this->registerReturningRow(fn (NewRegistration $r) => new RegisteredAccount($r->accounts[0]->id, false, catchUpDays: null));
        $handover = $this->registerReturningRow(fn () => new RegisteredAccount('taken-over', true, $old, catchUpDays: null, handover: true));

        $this->assertTrue($reattached->missedUnknown);
        $this->assertNull($reattached->missed);
        $this->assertSame('2026-09-01 07:00 +07:00', $reattached->disconnectedSince?->format('Y-m-d H:i P'));
        $this->assertTrue($neverPolled->missedUnknown);
        $this->assertNull($neverPolled->disconnectedSince);
        $this->assertFalse($new->missedUnknown);
        $this->assertFalse($handover->missedUnknown);
        $this->assertNull($handover->missed);
    }

    public function test_account_states_are_asked_with_the_same_fingerprints_register_would_send(): void
    {
        $registrar = $this->registrarReturning(
            fn (NewRegistration $r) => array_map(fn ($a) => new RegisteredAccount($a->id, false), $r->accounts),
            fn (array $fingerprints) => array_combine($fingerprints, [AccountState::New, AccountState::Reattachable, AccountState::UserBound]),
        );
        $accounts = ['tok-a' => self::accounts()[0], 'tok-b' => self::accounts()[1], 'tok-c' => self::accounts()[2]];

        $states = $registrar->accountStates(str_repeat("\x01", 32), new BankSession('t', 'u', 'ORG', 'c'), $accounts);
        $this->register($registrar);

        $this->assertSame(['tok-a' => AccountState::New, 'tok-b' => AccountState::Reattachable, 'tok-c' => AccountState::UserBound], $states);
        $query = $this->stateQueries[0];
        $sent = $this->sent[0];
        $this->assertSame(str_repeat("\x01", 32), $query['code']);
        $this->assertSame($sent->orgFingerprint, $query['org']);
        $this->assertSame($sent->userFingerprint, $query['user']);
        $this->assertSame($sent->accounts[0]->fingerprint, $query['fingerprints'][0]);
    }

    public function test_a_state_answer_missing_an_account_is_a_contract_violation(): void
    {
        $registrar = $this->registrarReturning(
            fn (NewRegistration $r) => [],
            fn (array $fingerprints) => [$fingerprints[0] => AccountState::New],
        );

        $this->expectException(RegistrationStoreUnavailable::class);
        $registrar->accountStates(str_repeat("\x01", 32), new BankSession('t', 'u', 'ORG', 'c'), ['a' => self::accounts()[0], 'b' => self::accounts()[1]]);
    }

    public function test_only_the_first_fifty_distinct_accounts_are_asked_about(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => []);
        $accounts = ['dup' => new BankAccount(AccountNumber::tryFrom('1000000000'), 'SA')];
        foreach (range(0, 51) as $i) {
            $accounts["tok-{$i}"] = new BankAccount(AccountNumber::tryFrom(sprintf('10000000%02d', $i)), 'SA');
        }

        $states = $registrar->accountStates(str_repeat("\x01", 32), new BankSession('t', 'u', 'ORG', 'c'), $accounts);

        $this->assertCount(1, $this->stateQueries);
        $this->assertCount(50, $this->stateQueries[0]['fingerprints']);
        $this->assertSame(['dup', ...array_map(fn (int $i) => "tok-{$i}", range(0, 49))], array_keys($states));
        $this->assertArrayNotHasKey('tok-50', $states);
    }

    public function test_no_listed_accounts_asks_nothing(): void
    {
        $registrar = $this->registrarReturning(fn (NewRegistration $r) => []);

        $this->assertSame([], $registrar->accountStates(str_repeat("\x01", 32), new BankSession('t', 'u', 'ORG', 'c'), []));
        $this->assertSame([], $this->stateQueries);
    }
}
