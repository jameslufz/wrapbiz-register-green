<?php

namespace Tests\Support;

use App\Wrapbiz\AccountState;
use App\Wrapbiz\AttemptReservation;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\NewRegistration;
use App\Wrapbiz\RegisteredAccount;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use App\Wrapbiz\RejectionReason;

/**
 * In-memory stand-in for the wrapbiz DB functions, following contract B:
 * codes lock after LOCK_AFTER failed logins and are consumed by a
 * successful register(); failed logins plus reserved attempts never exceed
 * LOCK_AFTER; account states answer at most STATES_CALLS calls and
 * RegistrationStore::MAX_STATES_FINGERPRINTS distinct fingerprints per code,
 * and a code that reached either is "exhausted" for new logins; a K BIZ
 * user is bound to the one account it first registered.
 */
final class RecordingStore implements RegistrationStore
{
    public const int LOCK_AFTER = 5;

    public const int STATES_CALLS = 10;

    /** @var list<NewRegistration> */
    public array $registrations = [];

    public ?\Throwable $failRegisterWith = null;

    /** Thrown once, after the registration was committed (a lost response). */
    public ?\Throwable $failAfterCommitWith = null;

    public bool $unavailable = false;

    public bool $recordFailureUnavailable = false;

    public bool $endAttemptUnavailable = false;

    /** @var array<string, int> code hash => reserved, unsettled login attempts */
    public array $inFlight = [];

    /** @var array<string, string> live reservation id => code hash */
    public array $reservations = [];

    public ?string $lastReservationId = null;

    private int $reservationCount = 0;

    /** @var list<string> 'begin:<status>', 'end:<reservation>' and 'record:<reservation or null>' in call order */
    public array $attemptLog = [];

    /** @var array<int, string> index into the sent accounts => existing account id returned as reattached */
    public array $reattachedIndexes = [];

    /** @var array<int, \DateTimeImmutable> index into the sent accounts => kept watermark of that reattached account */
    public array $watermarks = [];

    /** @var array<int, \DateTimeImmutable> index into the sent accounts => original registration time of that reattached account */
    public array $registeredAt = [];

    /** @var array<int, array{?\DateTimeImmutable, ?\DateTimeImmutable, ?int, ?int}> index into the sent accounts => that reattached account is a hand-over with this gap, delivered and pending count */
    public array $handovers = [];

    /** What register_connection() returns as catchup_days on every row. */
    public mixed $catchUpDays = 7;

    /** @var array<string, AccountState> raw account fingerprint => state; unlisted fingerprints are new */
    public array $accountStates = [];

    public bool $accountStatesUnavailable = false;

    /** @var list<array{org: string, user: string, fingerprints: list<string>}> */
    public array $accountStateCalls = [];

    /** @var array<string, int> code hash => account-state calls answered */
    public array $statesCalls = [];

    /** @var array<string, array<string, true>> code hash => distinct fingerprints asked about */
    public array $statesFingerprints = [];

    /** @var array<string, true> code hashes whose states call was refused; the database commits this mark */
    public array $statesRefused = [];

    /** @var array<string, string> raw org fingerprint . raw user fingerprint => the raw account fingerprint that K BIZ user is bound to */
    public array $userBindings = [];

    /** @var array<string, CodeStatus> code hash => status */
    private array $codes = [];

    /** @var array<string, int> code hash => failed logins */
    public array $failedLogins = [];

    /**
     * @param  list<string>  $usableCodes
     */
    public function __construct(array $usableCodes)
    {
        foreach ($usableCodes as $code) {
            $this->codes[hash('sha256', $code, true)] = CodeStatus::Usable;
        }
    }

    public function setStatus(string $code, CodeStatus $status): void
    {
        $this->codes[hash('sha256', $code, true)] = $status;
    }

    public function statusOf(string $code): CodeStatus
    {
        return $this->codes[hash('sha256', $code, true)] ?? CodeStatus::Unknown;
    }

    public function codeStatus(string $codeHash): CodeStatus
    {
        if ($this->unavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }

        return $this->effectiveStatus($codeHash);
    }

    public function spendStatesBudget(string $code): void
    {
        $this->statesCalls[hash('sha256', $code, true)] = self::STATES_CALLS;
    }

    private function effectiveStatus(string $codeHash): CodeStatus
    {
        $status = $this->codes[$codeHash] ?? CodeStatus::Unknown;
        $spent = ($this->statesCalls[$codeHash] ?? 0) >= self::STATES_CALLS
            || count($this->statesFingerprints[$codeHash] ?? []) >= self::MAX_STATES_FINGERPRINTS
            || isset($this->statesRefused[$codeHash]);

        return $status === CodeStatus::Usable && $spent ? CodeStatus::Exhausted : $status;
    }

    public function beginLoginAttempt(string $codeHash): AttemptReservation
    {
        if ($this->unavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }

        $attempt = match ($this->effectiveStatus($codeHash)) {
            CodeStatus::Usable => ($this->failedLogins[$codeHash] ?? 0) + ($this->inFlight[$codeHash] ?? 0) >= self::LOCK_AFTER
                ? LoginAttempt::Busy
                : LoginAttempt::Reserved,
            CodeStatus::Unknown => LoginAttempt::Unknown,
            CodeStatus::Used => LoginAttempt::Used,
            CodeStatus::Expired => LoginAttempt::Expired,
            CodeStatus::Locked => LoginAttempt::Locked,
            CodeStatus::Exhausted => LoginAttempt::Exhausted,
        };
        $this->attemptLog[] = 'begin:'.$attempt->value;
        if ($attempt !== LoginAttempt::Reserved) {
            return AttemptReservation::refused($attempt);
        }

        $reservationId = sprintf('00000000-0000-4000-8000-%012d', ++$this->reservationCount);
        $this->lastReservationId = $reservationId;
        $this->reservations[$reservationId] = $codeHash;
        $this->inFlight[$codeHash] = ($this->inFlight[$codeHash] ?? 0) + 1;

        return AttemptReservation::reserved($reservationId);
    }

    public function endLoginAttempt(string $codeHash, string $reservationId): void
    {
        $this->attemptLog[] = 'end:'.$reservationId;
        if ($this->unavailable || $this->endAttemptUnavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }
        $this->release($codeHash, $reservationId);
    }

    public function recordFailedLogin(string $codeHash, ?string $reservationId): bool
    {
        $this->attemptLog[] = 'record:'.($reservationId ?? 'null');
        if ($this->unavailable || $this->recordFailureUnavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }
        if ($reservationId !== null) {
            $this->release($codeHash, $reservationId);
        }
        if (($this->codes[$codeHash] ?? null) !== CodeStatus::Usable) {
            return false;
        }

        $this->failedLogins[$codeHash] = ($this->failedLogins[$codeHash] ?? 0) + 1;
        if ($this->failedLogins[$codeHash] >= self::LOCK_AFTER) {
            $this->codes[$codeHash] = CodeStatus::Locked;

            return true;
        }

        return false;
    }

    /** Like the database: only the named reservation of this code, and only once. */
    private function release(string $codeHash, string $reservationId): void
    {
        if (($this->reservations[$reservationId] ?? null) !== $codeHash) {
            return;
        }
        unset($this->reservations[$reservationId]);
        $this->inFlight[$codeHash]--;
    }

    public function accountStates(string $codeHash, string $orgFingerprint, string $userFingerprint, array $fingerprints): array
    {
        $this->accountStateCalls[] = ['org' => $orgFingerprint, 'user' => $userFingerprint, 'fingerprints' => $fingerprints];
        if ($this->unavailable || $this->accountStatesUnavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }
        // Like the database: an exhausted code is refused by the budget, not as unusable.
        if (($this->codes[$codeHash] ?? null) !== CodeStatus::Usable) {
            throw new RegistrationRejected(RejectionReason::CodeUnusable);
        }
        $seen = ($this->statesFingerprints[$codeHash] ?? []) + array_fill_keys($fingerprints, true);
        if (($this->statesCalls[$codeHash] ?? 0) >= self::STATES_CALLS || count($seen) > self::MAX_STATES_FINGERPRINTS) {
            $this->statesRefused[$codeHash] = true;

            throw new RegistrationRejected(RejectionReason::StatesBudgetExhausted);
        }
        $this->statesCalls[$codeHash] = ($this->statesCalls[$codeHash] ?? 0) + 1;
        $this->statesFingerprints[$codeHash] = $seen;

        $boundTo = $this->userBindings[$orgFingerprint.$userFingerprint] ?? null;
        $states = [];
        foreach ($fingerprints as $fingerprint) {
            $states[$fingerprint] = $boundTo !== null && $boundTo !== $fingerprint
                ? AccountState::UserBound
                : $this->accountStates[$fingerprint] ?? AccountState::New;
        }

        return $states;
    }

    public function register(NewRegistration $registration): array
    {
        if ($this->failRegisterWith !== null) {
            throw $this->failRegisterWith;
        }
        if ($this->unavailable) {
            throw new RegistrationStoreUnavailable('08006');
        }
        if (count($registration->accounts) !== 1) {
            throw new RegistrationRejected(RejectionReason::InvalidAccounts);
        }
        // The account-state budget only stops new bank logins; a login that
        // already listed its accounts may still register.
        if (($this->codes[$registration->codeHash] ?? null) !== CodeStatus::Usable) {
            throw new RegistrationRejected(RejectionReason::CodeUnusable);
        }
        $fingerprint = $registration->accounts[0]->fingerprint;
        $user = $registration->orgFingerprint.$registration->userFingerprint;
        $boundTo = $this->userBindings[$user] ?? null;
        if ($boundTo !== null && $boundTo !== $fingerprint) {
            throw new RegistrationRejected(RejectionReason::UserAlreadyRegistered);
        }

        $this->registrations[] = $registration;
        $this->userBindings[$user] = $fingerprint;
        $this->codes[$registration->codeHash] = CodeStatus::Used;

        if ($this->failAfterCommitWith !== null) {
            $exception = $this->failAfterCommitWith;
            $this->failAfterCommitWith = null;

            throw $exception;
        }

        $results = [];
        foreach ($registration->accounts as $index => $account) {
            $results[] = isset($this->reattachedIndexes[$index])
                ? new RegisteredAccount($this->reattachedIndexes[$index], true, $this->watermarks[$index] ?? null, $this->registeredAt[$index] ?? null, $this->catchUpDays,
                    isset($this->handovers[$index]), $this->handovers[$index][0] ?? null, $this->handovers[$index][1] ?? null, $this->handovers[$index][2] ?? null, $this->handovers[$index][3] ?? null)
                : new RegisteredAccount($account->id, false, catchUpDays: $this->catchUpDays);
        }

        return $results;
    }
}
