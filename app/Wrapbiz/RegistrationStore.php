<?php

namespace App\Wrapbiz;

interface RegistrationStore
{
    /**
     * registration_account_states() answers at most this many fingerprints
     * per call, and at most this many distinct ones over a code's life.
     */
    public const int MAX_STATES_FINGERPRINTS = 50;

    /**
     * Read-only; the code is only consumed by register().
     *
     * @throws RegistrationStoreUnavailable
     */
    public function codeStatus(string $codeHash): CodeStatus;

    /**
     * Reserves one of the code's attempt slots right before its credentials
     * go to the bank, so parallel logins cannot together exceed the lock
     * limit. Anything but Reserved means the bank must not be contacted.
     *
     * @throws RegistrationStoreUnavailable
     */
    public function beginLoginAttempt(string $codeHash): AttemptReservation;

    /**
     * Releases exactly this reservation when its outcome does not count: a
     * QR challenge was shown, or the bank was never reached.
     *
     * @throws RegistrationStoreUnavailable
     */
    public function endLoginAttempt(string $codeHash, string $reservationId): void;

    /**
     * Counts a failed bank login against a usable code and releases the
     * given reservation: any answer to the credential submission other than
     * a QR challenge, or (with no reservation, its slot was released when
     * the QR was shown) a rejected approval.
     *
     * @return bool true when the code is now locked
     *
     * @throws RegistrationStoreUnavailable
     */
    public function recordFailedLogin(string $codeHash, ?string $reservationId): bool;

    /**
     * Answers only while the code is usable, and only within the code's
     * budget: at most 10 calls and MAX_STATES_FINGERPRINTS distinct
     * fingerprints over its life (StatesBudgetExhausted beyond that). Each
     * call is audited and spends that budget, so ask once per account list.
     *
     * @param  string  $orgFingerprint  raw 32-byte HMAC of the bank organisation id
     * @param  string  $userFingerprint  raw 32-byte HMAC of the bank user reference
     * @param  list<string>  $fingerprints  distinct raw 32-byte account fingerprints, at most MAX_STATES_FINGERPRINTS
     * @return array<string, AccountState> keyed by raw fingerprint, one entry for each one asked about
     *
     * @throws RegistrationRejected
     * @throws RegistrationStoreUnavailable
     */
    public function accountStates(string $codeHash, string $orgFingerprint, string $userFingerprint, array $fingerprints): array;

    /**
     * @return non-empty-list<RegisteredAccount> one row per account, in the order they were sent
     *
     * @throws RegistrationRejected
     * @throws RegistrationStoreUnavailable
     */
    public function register(NewRegistration $registration): array;
}
