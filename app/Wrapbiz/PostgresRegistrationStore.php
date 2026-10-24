<?php

namespace App\Wrapbiz;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use PDOException;

/**
 * The only database interface of this app: six SECURITY DEFINER functions.
 * Binary values travel as hex/base64 text and are decoded by PostgreSQL.
 */
final readonly class PostgresRegistrationStore implements RegistrationStore
{
    private const string RAISE_EXCEPTION = 'P0001';

    private const string CHECK_VIOLATION = '23514';

    private const string CONTRACT_VIOLATION = 'contract';

    /** registration_account_states() answers a budget refusal with this single row, fingerprint NULL. */
    private const string BUDGET_REFUSAL_STATE = 'budget_exhausted';

    private const string UTC_TIMESTAMP_FORMAT = 'YYYY-MM-DD"T"HH24:MI:SS"Z"';

    private const string UTC_TIMESTAMP_PHP_FORMAT = 'Y-m-d\\TH:i:s\\Z';

    /** The worker's upper bound for POLL_CATCHUP_MAX_DAYS. */
    private const int MAX_CATCHUP_DAYS = 31;

    public function __construct(private ConnectionInterface $db) {}

    public function codeStatus(string $codeHash): CodeStatus
    {
        $row = $this->run(fn () => $this->db->selectOne(
            "select registration_code_usable(decode(?, 'hex')) as status",
            [bin2hex($codeHash)],
        ));

        $status = is_string($row->status ?? null) ? CodeStatus::tryFrom($row->status) : null;

        return $status ?? throw $this->contractViolation('registration_code_usable');
    }

    public function beginLoginAttempt(string $codeHash): AttemptReservation
    {
        $row = $this->run(fn () => $this->db->selectOne(
            "select status, reservation_id::text as reservation_id from registration_code_begin_attempt(decode(?, 'hex'))",
            [bin2hex($codeHash)],
        ));

        $attempt = is_string($row->status ?? null) ? LoginAttempt::tryFrom($row->status) : null;
        $reservationId = $row->reservation_id ?? null;
        try {
            return match (true) {
                $attempt === LoginAttempt::Reserved && is_string($reservationId) => AttemptReservation::reserved($reservationId),
                $attempt !== null && $attempt !== LoginAttempt::Reserved && $reservationId === null => AttemptReservation::refused($attempt),
                default => throw $this->contractViolation('registration_code_begin_attempt'),
            };
        } catch (InvalidArgumentException) {
            throw $this->contractViolation('registration_code_begin_attempt');
        }
    }

    public function endLoginAttempt(string $codeHash, string $reservationId): void
    {
        $this->run(fn () => $this->db->selectOne(
            "select registration_code_end_attempt(decode(?, 'hex'), ?::uuid)",
            [bin2hex($codeHash), $reservationId],
        ));
    }

    public function recordFailedLogin(string $codeHash, ?string $reservationId): bool
    {
        $row = $this->run(fn () => $this->db->selectOne(
            "select registration_code_record_failure(decode(?, 'hex'), ?::uuid) as locked",
            [bin2hex($codeHash), $reservationId],
        ));

        $locked = $row->locked ?? null;

        return is_bool($locked) ? $locked : throw $this->contractViolation('registration_code_record_failure');
    }

    public function accountStates(string $codeHash, string $orgFingerprint, string $userFingerprint, array $fingerprints): array
    {
        if ($fingerprints === []) {
            return [];
        }
        if (count($fingerprints) > RegistrationStore::MAX_STATES_FINGERPRINTS) {
            throw new InvalidArgumentException('registration_account_states() answers at most '.RegistrationStore::MAX_STATES_FINGERPRINTS.' fingerprints');
        }

        $placeholders = implode(', ', array_fill(0, count($fingerprints), "decode(?, 'hex')"));
        $rows = $this->runStates(count($fingerprints), fn () => $this->db->select(
            "select encode(fingerprint, 'hex') as fingerprint, state
               from registration_account_states(
                    p_code_hash => decode(?, 'hex'),
                    p_org_fingerprint => decode(?, 'hex'),
                    p_user_fingerprint => decode(?, 'hex'),
                    p_fingerprints => array[{$placeholders}]::bytea[])",
            [bin2hex($codeHash), bin2hex($orgFingerprint), bin2hex($userFingerprint), ...array_map(bin2hex(...), $fingerprints)],
        ));

        if (count($rows) === 1 && ($rows[0]->fingerprint ?? null) === null && ($rows[0]->state ?? null) === self::BUDGET_REFUSAL_STATE) {
            self::logBudgetRefusal(count($fingerprints));

            throw new RegistrationRejected(RejectionReason::StatesBudgetExhausted);
        }

        $asked = array_flip(array_map(bin2hex(...), $fingerprints));
        $states = [];
        foreach ($rows as $row) {
            $hex = $row->fingerprint ?? null;
            $state = is_string($row->state ?? null) ? AccountState::tryFrom($row->state) : null;
            if (! is_string($hex) || ! isset($asked[$hex]) || $state === null) {
                throw $this->contractViolation('registration_account_states');
            }
            $raw = (string) hex2bin($hex);
            if (isset($states[$raw])) {
                throw $this->contractViolation('registration_account_states');
            }
            $states[$raw] = $state;
        }
        if (count($states) !== count($asked)) {
            throw $this->contractViolation('registration_account_states');
        }

        return $states;
    }

    public function register(NewRegistration $registration): array
    {
        $accounts = array_map(fn (NewAccount $account) => [
            'id' => $account->id,
            'fingerprint' => bin2hex($account->fingerprint),
            'masked' => $account->masked,
            'sealed' => base64_encode($account->sealed),
        ], $registration->accounts);

        // Named arguments: the two fingerprints have the same type and size,
        // so a positional mix-up would go unnoticed.
        $rows = $this->run(fn () => $this->db->select(
            "select account_id::text as account_id, reattached,
                    to_char(last_success_at at time zone 'UTC', '".self::UTC_TIMESTAMP_FORMAT."') as last_success_at,
                    to_char(registered_at at time zone 'UTC', '".self::UTC_TIMESTAMP_FORMAT."') as registered_at,
                    catchup_days,
                    to_char(gap_from at time zone 'UTC', '".self::UTC_TIMESTAMP_FORMAT."') as gap_from,
                    to_char(gap_to at time zone 'UTC', '".self::UTC_TIMESTAMP_FORMAT."') as gap_to,
                    handover, gap_delivered_count, gap_pending_count
               from register_connection(
                    p_code_hash => decode(?, 'hex'),
                    p_provider => ?,
                    p_webhook_url => ?,
                    p_connection_id => ?::uuid,
                    p_sealed_cred => decode(?, 'base64'),
                    p_org_fingerprint => decode(?, 'hex'),
                    p_user_fingerprint => decode(?, 'hex'),
                    p_accounts => ?::jsonb,
                    p_ip_hash => decode(?, 'hex'))",
            [
                bin2hex($registration->codeHash),
                $registration->provider,
                $registration->webhookUrl,
                $registration->connectionId,
                base64_encode($registration->sealedCredential),
                bin2hex($registration->orgFingerprint),
                bin2hex($registration->userFingerprint),
                json_encode($accounts, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                bin2hex($registration->ipHash),
            ],
        ));

        $registered = [];
        foreach ($rows as $row) {
            if (! is_string($row->account_id ?? null) || ! is_bool($row->reattached ?? null) || ! is_bool($row->handover ?? null)
                || ! property_exists($row, 'gap_from') || ! property_exists($row, 'gap_to') || ! property_exists($row, 'gap_delivered_count')
                || ! property_exists($row, 'gap_pending_count')
            ) {
                throw $this->contractViolation('register_connection');
            }
            $registered[] = new RegisteredAccount(
                $row->account_id,
                $row->reattached,
                $row->reattached ? self::timestamp('last_success_at', $row->last_success_at ?? null) : null,
                $row->reattached ? self::timestamp('registered_at', $row->registered_at ?? null) : null,
                self::catchUpDays($row->catchup_days ?? null),
                $row->handover,
                ...($row->handover ? self::handoverGap($row->gap_from, $row->gap_to, $row->gap_delivered_count, $row->gap_pending_count) : []),
            );
        }
        if ($registered === []) {
            throw $this->contractViolation('register_connection');
        }

        return $registered;
    }

    /**
     * The registration has committed by the time this runs, so a value that
     * cannot be read only hides the missed-range notice (the worker alerts
     * the operator about long gaps anyway) instead of failing the request.
     */
    private static function timestamp(string $column, mixed $value): ?DateTimeImmutable
    {
        if ($value === null) {
            return null;
        }

        $parsed = is_string($value)
            ? DateTimeImmutable::createFromFormat('!'.self::UTC_TIMESTAMP_PHP_FORMAT, $value, new DateTimeZone('UTC'))
            : false;
        if ($parsed === false || $parsed->format(self::UTC_TIMESTAMP_PHP_FORMAT) !== $value) {
            Log::warning('register_connection returned an unreadable timestamp', ['column' => $column]);

            return null;
        }

        return $parsed;
    }

    /**
     * Read after commit, like the other timestamps: an empty gap is no gap,
     * and one that cannot be read, or is half missing or inverted, is left
     * out with a warning (the worker reports every hand-over gap to the
     * operator as well). An unreadable count only hides that count.
     *
     * @return array{gapFrom: ?DateTimeImmutable, gapTo: ?DateTimeImmutable, gapDeliveredCount: ?int, gapPendingCount: ?int}
     */
    private static function handoverGap(mixed $from, mixed $to, mixed $deliveredCount, mixed $pendingCount): array
    {
        $none = ['gapFrom' => null, 'gapTo' => null, 'gapDeliveredCount' => null, 'gapPendingCount' => null];
        if ($from === null && $to === null) {
            return $none;
        }

        $gapFrom = self::timestamp('gap_from', $from);
        $gapTo = self::timestamp('gap_to', $to);
        if ($gapFrom !== null && $gapFrom == $gapTo) {
            return $none;
        }
        if ($gapFrom === null || $gapTo === null || $gapFrom > $gapTo) {
            Log::warning('register_connection returned an unusable handover gap');

            return $none;
        }

        return [
            'gapFrom' => $gapFrom,
            'gapTo' => $gapTo,
            'gapDeliveredCount' => self::eventCount('gap_delivered_count', $deliveredCount),
            'gapPendingCount' => self::eventCount('gap_pending_count', $pendingCount),
        ];
    }

    private static function eventCount(string $column, mixed $value): ?int
    {
        if (is_string($value) && preg_match('/^[0-9]{1,9}$/D', $value) === 1) {
            $value = (int) $value;
        }
        if (is_int($value) && $value >= 0) {
            return $value;
        }

        Log::warning('register_connection returned an unreadable value', ['column' => $column]);

        return null;
    }

    /**
     * Read after commit, like the timestamps: a value that is NULL (the
     * database has no audited catch-up limit, wrapbiz migration 3: its claims
     * are refused too, and `migrate verify` says why) or cannot be read
     * replaces the missed-range notice with a warning that the range is
     * unknown.
     */
    private static function catchUpDays(mixed $value): ?int
    {
        if ($value === null) {
            Log::warning('register_connection returned no audited catch-up limit; the wrapbiz operator must run migrate verify',
                ['column' => 'catchup_days']);

            return null;
        }
        if (is_string($value) && preg_match('/^[0-9]{1,2}$/D', $value) === 1) {
            $value = (int) $value;
        }
        if (is_int($value) && $value >= 1 && $value <= self::MAX_CATCHUP_DAYS) {
            return $value;
        }

        Log::warning('register_connection returned an unreadable value', ['column' => 'catchup_days']);

        return null;
    }

    /**
     * Older databases refuse an over-budget call by raising
     * states_budget_exhausted instead of answering with the refusal row.
     *
     * @template T
     *
     * @param  callable(): T  $query
     * @return T
     */
    private function runStates(int $fingerprintCount, callable $query): mixed
    {
        try {
            return $this->run($query);
        } catch (RegistrationRejected $rejection) {
            if ($rejection->reason === RejectionReason::StatesBudgetExhausted) {
                self::logBudgetRefusal($fingerprintCount);
            }

            throw $rejection;
        }
    }

    /**
     * Only how many accounts were asked about; never which.
     */
    private static function logBudgetRefusal(int $fingerprintCount): void
    {
        Log::warning('registration_account_states refused: states_budget_exhausted', ['fingerprints' => $fingerprintCount]);
    }

    /**
     * @template T
     *
     * @param  callable(): T  $query
     * @return T
     */
    private function run(callable $query): mixed
    {
        try {
            return $query();
        } catch (QueryException|PDOException $exception) {
            throw $this->translate($exception);
        }
    }

    private function translate(QueryException|PDOException $exception): RegistrationRejected|RegistrationStoreUnavailable
    {
        $info = $exception->errorInfo;
        $sqlState = is_array($info) && is_string($info[0] ?? null) ? $info[0] : 'unknown';
        $driverMessage = is_array($info) && is_string($info[2] ?? null) ? $info[2] : '';

        if ($sqlState === self::CHECK_VIOLATION) {
            Log::warning('wrapbiz database refused registration input', ['sqlstate' => $sqlState]);

            return new RegistrationRejected(RejectionReason::InvalidInput);
        }
        if ($sqlState === self::RAISE_EXCEPTION) {
            foreach (RejectionReason::cases() as $reason) {
                if ($reason !== RejectionReason::InvalidInput && preg_match('/\b'.$reason->value.'\b/', $driverMessage) === 1) {
                    return new RegistrationRejected($reason);
                }
            }
        }

        Log::error('wrapbiz database call failed', ['sqlstate' => $sqlState]);

        return new RegistrationStoreUnavailable($sqlState);
    }

    private function contractViolation(string $function): RegistrationStoreUnavailable
    {
        Log::error('wrapbiz database returned an unexpected result', ['function' => $function]);

        return new RegistrationStoreUnavailable(self::CONTRACT_VIOLATION);
    }
}
