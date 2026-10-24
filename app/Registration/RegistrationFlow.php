<?php

namespace App\Registration;

use App\Kbiz\BankAccount;
use App\Kbiz\BankSession;
use App\Kbiz\QrChallenge;
use App\Security\AccountNumber;
use App\Wrapbiz\AccountState;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Contracts\Session\Session;

/**
 * Typed view over the (encrypted, short-lived) session for one registration.
 * Holds the register-code hash, the webhook URL and the bank state needed
 * between requests. The bank password is never stored here.
 */
final readonly class RegistrationFlow
{
    private const string KEY = 'registration';

    public function __construct(private Session $session) {}

    public function stage(): ?Stage
    {
        $stage = $this->session->get(self::KEY.'.stage');

        return is_string($stage) ? Stage::tryFrom($stage) : null;
    }

    /**
     * Starts a fresh registration; any earlier progress is discarded.
     */
    public function acceptCode(string $codeHash): void
    {
        $this->session->put(self::KEY, [
            'stage' => Stage::CodeAccepted->value,
            'code_hash' => bin2hex($codeHash),
        ]);
    }

    public function codeHash(): ?string
    {
        $hex = $this->session->get(self::KEY.'.code_hash');
        $raw = is_string($hex) ? hex2bin($hex) : false;

        return $raw === false ? null : $raw;
    }

    public function awaitApproval(string $webhookUrl, CookieJar $jar, QrChallenge $qr): void
    {
        $this->session->put(self::KEY.'.stage', Stage::AwaitingApproval->value);
        $this->session->put(self::KEY.'.webhook_url', $webhookUrl);
        $this->session->put(self::KEY.'.qr', ['image' => $qr->imageDataUri, 'expires_at' => $qr->expiresAt]);
        $this->saveBankCookies($jar);
    }

    public function webhookUrl(): ?string
    {
        $url = $this->session->get(self::KEY.'.webhook_url');

        return is_string($url) ? $url : null;
    }

    public function qr(): ?QrChallenge
    {
        $qr = $this->session->get(self::KEY.'.qr');
        if (! is_array($qr) || ! is_string($qr['image'] ?? null) || ! is_int($qr['expires_at'] ?? null)) {
            return null;
        }

        return new QrChallenge($qr['image'], $qr['expires_at']);
    }

    public function bankCookies(): CookieJar
    {
        $cookies = $this->session->get(self::KEY.'.bank_cookies');

        return new CookieJar(false, is_array($cookies) ? $cookies : []);
    }

    public function saveBankCookies(CookieJar $jar): void
    {
        $this->session->put(self::KEY.'.bank_cookies', $jar->toArray());
    }

    /**
     * The bank login is complete: the cookie jar and QR are no longer needed,
     * only the session the worker will poll with. The list gets a fresh
     * nonce and every account an opaque token, so a form rendered for an
     * earlier list (another tab, the back button) can never select from
     * this one.
     *
     * @param  list<BankAccount>  $accounts
     */
    public function chooseAccounts(BankSession $bankSession, array $accounts): void
    {
        $this->forgetBankLogin();
        $this->session->forget(self::KEY.'.account_states');
        $this->session->put(self::KEY.'.stage', Stage::ChoosingAccounts->value);
        $this->session->put(self::KEY.'.bank_session', $bankSession->toArray());
        $this->session->put(self::KEY.'.list_nonce', self::randomToken());
        $this->session->put(self::KEY.'.accounts', array_map(
            fn (BankAccount $account) => ['token' => self::randomToken(), 'number' => $account->number->digits, 'kind' => $account->kind],
            $accounts,
        ));
    }

    public function listNonce(): ?string
    {
        $nonce = $this->session->get(self::KEY.'.list_nonce');

        return is_string($nonce) ? $nonce : null;
    }

    public function bankSession(): ?BankSession
    {
        $data = $this->session->get(self::KEY.'.bank_session');

        return is_array($data) ? BankSession::fromArray($data) : null;
    }

    /**
     * @return array<string, BankAccount> keyed by the opaque token shown in the form
     */
    public function accounts(): array
    {
        $rows = $this->session->get(self::KEY.'.accounts');
        $accounts = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            $number = AccountNumber::tryFrom($row['number'] ?? null);
            $token = $row['token'] ?? null;
            if ($number !== null && is_string($token)) {
                $accounts[$token] = new BankAccount($number, is_string($row['kind'] ?? null) ? $row['kind'] : '');
            }
        }

        return $accounts;
    }

    /**
     * What the database said about the listed accounts, kept for this list
     * only so that viewing it again does not spend the code's state budget.
     * Only these, never the form, decide what may be submitted, and
     * register_connection() checks every account again.
     *
     * @param  array<string, AccountState>  $states  keyed by account token; accounts not asked about are absent
     */
    public function rememberAccountStates(array $states): void
    {
        $this->session->put(self::KEY.'.account_states', [
            'list' => $this->listNonce(),
            'states' => array_map(fn (AccountState $state) => $state->value, $states),
        ]);
    }

    public function forgetAccountStates(): void
    {
        $this->session->forget(self::KEY.'.account_states');
    }

    /**
     * @return ?array<string, AccountState> keyed by account token; null when this list's states are not known
     */
    public function accountStates(): ?array
    {
        $stored = $this->session->get(self::KEY.'.account_states');
        $listNonce = $this->listNonce();
        if (! is_array($stored) || $listNonce === null || ($stored['list'] ?? null) !== $listNonce || ! is_array($stored['states'] ?? null)) {
            return null;
        }

        $states = [];
        foreach ($stored['states'] as $token => $value) {
            $state = is_string($value) ? AccountState::tryFrom($value) : null;
            if ($state === null) {
                return null;
            }
            $states[(string) $token] = $state;
        }

        return $states;
    }

    /**
     * Drops every bank artefact but keeps the accepted code, so the customer
     * can retry the bank login without re-entering it.
     */
    public function backToLogin(): void
    {
        $this->forgetBankLogin();
        $this->session->forget([self::KEY.'.bank_session', self::KEY.'.accounts', self::KEY.'.list_nonce', self::KEY.'.account_states']);
        $this->session->put(self::KEY.'.stage', Stage::CodeAccepted->value);
    }

    public function clear(): void
    {
        $this->session->forget(self::KEY);
    }

    private function forgetBankLogin(): void
    {
        $this->session->forget([self::KEY.'.bank_cookies', self::KEY.'.qr']);
    }

    private static function randomToken(): string
    {
        return bin2hex(random_bytes(16));
    }
}
