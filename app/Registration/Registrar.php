<?php

namespace App\Registration;

use App\Kbiz\BankAccount;
use App\Kbiz\BankSession;
use App\Security\AccountFingerprinter;
use App\Security\CredentialSealer;
use App\Security\IpHasher;
use App\Wrapbiz\AccountState;
use App\Wrapbiz\NewAccount;
use App\Wrapbiz\NewRegistration;
use App\Wrapbiz\RegisteredAccount;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Turns a finished bank login into registration_account_states() and
 * register_connection() calls. Everything secret is sealed to the worker
 * before it leaves this process.
 */
final readonly class Registrar
{
    public const string PROVIDER = 'kbank';

    /**
     * @param  string  $provider  must equal the database's wrapbiz_bank(); only the integration tests' scratch databases use another
     */
    public function __construct(
        private CredentialSealer $sealer,
        private AccountFingerprinter $fingerprinter,
        private IpHasher $ipHasher,
        private RegistrationStore $store,
        private string $provider = self::PROVIDER,
    ) {}

    /**
     * Asks about the first MAX_STATES_FINGERPRINTS distinct accounts in list
     * order only: the code's budget allows no more over its life, so later
     * accounts get no state and cannot be selected.
     *
     * @param  array<string, BankAccount>  $accounts  keyed by any caller token
     * @return array<string, AccountState> keyed by the same tokens, for the accounts that were asked about
     *
     * @throws RegistrationRejected
     * @throws RegistrationStoreUnavailable
     */
    public function accountStates(string $codeHash, BankSession $bankSession, array $accounts): array
    {
        $fingerprints = array_map(fn (BankAccount $account) => $this->fingerprinter->fingerprint($this->provider, $account->number), $accounts);
        $asked = array_slice(array_values(array_unique($fingerprints)), 0, RegistrationStore::MAX_STATES_FINGERPRINTS);
        if ($asked === []) {
            return [];
        }

        $states = $this->store->accountStates(
            $codeHash,
            $this->fingerprinter->organisation($this->provider, $bankSession->orgId),
            $this->fingerprinter->user($this->provider, $bankSession->userRef),
            $asked,
        );

        $askedSet = array_flip($asked);
        $byToken = [];
        foreach ($fingerprints as $token => $fingerprint) {
            if (isset($askedSet[$fingerprint])) {
                $byToken[$token] = $states[$fingerprint] ?? throw new RegistrationStoreUnavailable('contract');
            }
        }

        return $byToken;
    }

    /**
     * A K BIZ user registers exactly one bank account, ever, so a
     * registration carries exactly one.
     *
     * @return non-empty-list<RegistrationResult>
     *
     * @throws RegistrationRejected
     * @throws RegistrationStoreUnavailable
     */
    public function register(
        string $codeHash,
        string $webhookUrl,
        BankSession $bankSession,
        BankAccount $account,
        string $clientIp,
    ): array {
        $connectionId = (string) Str::uuid7();
        $accountId = (string) Str::uuid7();
        $newAccounts = [new NewAccount(
            id: $accountId,
            fingerprint: $this->fingerprinter->fingerprint($this->provider, $account->number),
            masked: $account->number->masked(),
            sealed: $this->sealer->seal([
                'account_id' => $accountId,
                'account_no' => $account->number->digits,
                'account_type' => $account->kind,
            ]),
        )];

        $registered = $this->store->register(new NewRegistration(
            codeHash: $codeHash,
            provider: $this->provider,
            webhookUrl: $webhookUrl,
            connectionId: $connectionId,
            sealedCredential: $this->sealer->seal(['connection_id' => $connectionId, ...$bankSession->toArray()]),
            orgFingerprint: $this->fingerprinter->organisation($this->provider, $bankSession->orgId),
            userFingerprint: $this->fingerprinter->user($this->provider, $bankSession->userRef),
            accounts: $newAccounts,
            ipHash: $this->ipHasher->hash($clientIp),
        ));

        return $this->results($newAccounts, $registered);
    }

    /**
     * New accounts come back with the id we generated. Reattached accounts
     * come back with their existing id, so only their position (the contract
     * returns rows in request order) identifies them; if the rows do not line
     * up, their masked number is left unknown rather than guessed.
     *
     * @param  list<NewAccount>  $sent
     * @param  non-empty-list<RegisteredAccount>  $registered
     * @return non-empty-list<RegistrationResult>
     */
    private function results(array $sent, array $registered): array
    {
        $maskedById = [];
        foreach ($sent as $account) {
            $maskedById[$account->id] = $account->masked;
        }

        $alignedByPosition = count($sent) === count($registered);
        foreach ($registered as $index => $row) {
            if ($alignedByPosition && ! $row->reattached && $row->id !== $sent[$index]->id) {
                $alignedByPosition = false;
            }
        }
        if (! $alignedByPosition) {
            Log::warning('register_connection rows did not line up with the request', [
                'sent' => count($sent),
                'returned' => count($registered),
            ]);
        }

        $now = now();

        return array_map(fn (RegisteredAccount $row, int $index) => self::result(
            $row,
            $maskedById[$row->id] ?? ($alignedByPosition ? $sent[$index]->masked : null),
            $now,
        ), $registered, array_keys($registered));
    }

    /**
     * A reattached account (not a hand-over, which starts fresh) gets the
     * range it will never deliver, or, when the database returned no
     * catch-up window (it has no audited limit), a warning that the range
     * cannot be told: never a range from a guessed window.
     */
    private static function result(RegisteredAccount $row, ?string $masked, DateTimeInterface $now): RegistrationResult
    {
        $catchesUp = $row->reattached && ! $row->handover;
        $pollingStart = $row->pollingStart();

        return new RegistrationResult(
            $row->id,
            $masked,
            $row->reattached,
            $row->catchUpDays,
            $catchesUp && $row->catchUpDays !== null ? MissedRange::between($pollingStart, $now, $row->catchUpDays) : null,
            $row->handover,
            $row->handover && $row->gapFrom !== null && $row->gapTo !== null
                ? HandoverGap::between($row->gapFrom, $row->gapTo, $row->gapDeliveredCount, $row->gapPendingCount)
                : null,
            $catchesUp && $row->catchUpDays === null,
            $catchesUp && $row->catchUpDays === null && $pollingStart !== null
                ? CarbonImmutable::instance($pollingStart)->setTimezone(MissedRange::TIMEZONE)
                : null,
        );
    }
}
