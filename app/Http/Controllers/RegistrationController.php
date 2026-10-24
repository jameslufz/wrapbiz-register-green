<?php

namespace App\Http\Controllers;

use App\Kbiz\ApprovalStatus;
use App\Kbiz\BankException;
use App\Kbiz\KbizClient;
use App\Registration\BankLoginBudget;
use App\Registration\Registrar;
use App\Registration\RegistrationFlow;
use App\Registration\Stage;
use App\Security\WebhookUrlValidator;
use App\Wrapbiz\AccountState;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use App\Wrapbiz\RejectionReason;
use App\Wrapbiz\WrapbizSettings;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\MessageBag;
use Illuminate\Support\ViewErrorBag;
use Illuminate\View\View;

final class RegistrationController extends Controller
{
    private const string MSG_SESSION_EXPIRED = 'เซสชันหมดอายุหรือยังไม่ได้เริ่มลงทะเบียน กรุณากรอกรหัสลงทะเบียนใหม่';

    private const string MSG_SERVICE_DOWN = 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้งในอีกสักครู่';

    private const string MSG_BANK_BUSY = 'มีผู้ใช้งานเข้าสู่ระบบธนาคารพร้อมกันจำนวนมาก กรุณารอสักครู่แล้วลองใหม่';

    private const string MSG_LOGIN_FAILED_WARNING = 'หากเข้าสู่ระบบไม่สำเร็จหลายครั้ง รหัสลงทะเบียนจะถูกล็อก';

    private const string MSG_LIST_CHANGED = 'รายการบัญชีมีการเปลี่ยนแปลง (อาจมีการเข้าสู่ระบบใหม่จากแท็บอื่น) กรุณาตรวจสอบและเลือกบัญชีใหม่จากรายการด้านล่าง';

    private const string MSG_INVALID_SELECTION = 'รายการบัญชีที่เลือกไม่ถูกต้อง กรุณาเลือกใหม่';

    private const string MSG_CHOOSE_ACCOUNT = 'กรุณาเลือก 1 บัญชีที่ต้องการลงทะเบียน';

    private const string MSG_STATES_UNKNOWN = 'ยังตรวจสอบสถานะบัญชีที่เลือกไม่ได้ กรุณาตรวจสอบรายการด้านล่างแล้วเลือกใหม่';

    private const string MSG_NOT_ASKED = 'รหัสลงทะเบียนหนึ่งรหัสตรวจสอบได้สูงสุด 50 บัญชี บัญชีนี้จึงเลือกไม่ได้ ติดต่อผู้ดูแล';

    private const string MSG_ALREADY_REGISTERED = 'บัญชีนี้ลงทะเบียนแล้ว ติดต่อผู้ดูแล (บัญชีที่เลือกถูกลงทะเบียนไว้ก่อนแล้ว ยังไม่มีการบันทึกข้อมูลใด ๆ)';

    private const string MSG_ENDPOINT_CONFLICT = 'บัญชีที่เลือกเคยลงทะเบียนไว้กับ Webhook URL คนละชุด จึงเชื่อมต่อใหม่พร้อมกันไม่ได้ ยังไม่มีการบันทึกข้อมูลใด ๆ กรุณาเลือกเฉพาะบัญชีที่เคยใช้ Webhook URL เดียวกัน หรือติดต่อผู้ดูแลระบบ';

    private const string MSG_ENDPOINT_URL_LOCKED = 'เปลี่ยน URL ไม่ได้ เพราะยังมีบัญชีอื่นใช้ endpoint นี้อยู่ ติดต่อผู้ดูแล';

    private const string MSG_ENDPOINT_DISABLED = 'endpoint นี้ถูกปิดโดยผู้ดูแล ติดต่อผู้ดูแล';

    private const string MSG_INVALID_INPUT = 'ข้อมูลการลงทะเบียนไม่ผ่านการตรวจสอบของระบบ ยังไม่มีการบันทึกข้อมูลใด ๆ กรุณาเริ่มใหม่และตรวจสอบ Webhook URL หากยังพบปัญหาโปรดติดต่อผู้ดูแลระบบ';

    private const string MSG_NOT_COMPLETED = 'ระบบขัดข้องชั่วคราว การลงทะเบียนยังไม่สำเร็จ กรุณากดลงทะเบียนอีกครั้ง';

    private const string MSG_OUTCOME_UNKNOWN = 'ระบบขัดข้อง ไม่สามารถยืนยันได้ว่าการลงทะเบียนสำเร็จหรือไม่ กรุณากดลงทะเบียนอีกครั้งในอีกสักครู่ หากระบบแจ้งว่ารหัสถูกใช้แล้ว แสดงว่าการลงทะเบียนอาจสำเร็จแล้ว โปรดติดต่อผู้ดูแลระบบเพื่อตรวจสอบ';

    /** Input that must never be written to the session, not even as "old input". */
    private const array NEVER_FLASHED = ['password', 'code'];

    private const int MIN_CODE_LENGTH = 16;

    private const int MAX_CODE_LENGTH = 256;

    public function showCode(Request $request): View
    {
        return view('registration.code', [
            'inProgress' => $this->flow($request)->stage(),
        ]);
    }

    public function submitCode(Request $request, RegistrationStore $store): RedirectResponse
    {
        $request->validate(
            ['code' => ['required', 'string', 'max:'.self::MAX_CODE_LENGTH]],
            ['code.required' => 'กรุณากรอกรหัสลงทะเบียน', 'code.max' => CodeStatus::Unknown->message()],
        );

        $code = trim($request->string('code')->toString());
        if (preg_match('/^[\x21-\x7E]{'.self::MIN_CODE_LENGTH.','.self::MAX_CODE_LENGTH.'}$/D', $code) !== 1) {
            return back()->withErrors(['code' => CodeStatus::Unknown->message()]);
        }

        $codeHash = hash('sha256', $code, true);
        try {
            $status = $store->codeStatus($codeHash);
        } catch (RegistrationStoreUnavailable) {
            return back()->withErrors(['code' => self::MSG_SERVICE_DOWN]);
        }
        if ($status !== CodeStatus::Usable) {
            return back()->withErrors(['code' => $status->message()]);
        }

        $request->session()->regenerate();
        $this->flow($request)->acceptCode($codeHash);

        return redirect()->route('registration.login');
    }

    public function showLogin(Request $request): View|RedirectResponse
    {
        $flow = $this->flow($request);
        if ($flow->stage() === null) {
            return $this->restartWith($request, self::MSG_SESSION_EXPIRED);
        }

        return view('registration.login', ['webhookUrl' => $flow->webhookUrl()]);
    }

    public function submitLogin(
        Request $request,
        KbizClient $bank,
        WebhookUrlValidator $webhookUrls,
        RegistrationStore $store,
        BankLoginBudget $budget,
    ): RedirectResponse {
        $flow = $this->flow($request);
        $codeHash = $flow->codeHash();
        if ($flow->stage() === null || $codeHash === null) {
            return $this->restartWith($request, self::MSG_SESSION_EXPIRED);
        }
        // A new login always replaces whatever an earlier login (in this or
        // another tab) left behind, even if this attempt fails.
        if ($flow->stage() !== Stage::CodeAccepted) {
            $flow->backToLogin();
        }

        $request->validate([
            'username' => ['required', 'string', 'max:100'],
            'password' => ['required', 'string', 'max:200'],
            'webhook_url' => ['required', 'string', 'max:'.WebhookUrlValidator::MAX_LENGTH],
        ], [
            'username.required' => 'กรุณากรอกชื่อผู้ใช้ K BIZ',
            'password.required' => 'กรุณากรอกรหัสผ่าน K BIZ',
            'webhook_url.required' => 'กรุณากรอก Webhook URL',
            'webhook_url.max' => 'URL ยาวเกิน 2,048 ตัวอักษร',
            '*.max' => 'ข้อมูลยาวเกินกำหนด',
        ]);

        $webhookUrl = trim($request->string('webhook_url')->toString());
        $problem = $webhookUrls->validate($webhookUrl);
        if ($problem !== null) {
            return $this->backToLoginForm($request, ['webhook_url' => $problem->message()]);
        }

        try {
            $reservation = $store->beginLoginAttempt($codeHash);
        } catch (RegistrationStoreUnavailable) {
            return $this->backToLoginForm($request, ['login' => self::MSG_SERVICE_DOWN]);
        }
        $reservationId = $reservation->reservationId;
        if ($reservation->attempt === LoginAttempt::Busy) {
            return $this->backToLoginForm($request, ['login' => $reservation->attempt->message()]);
        }
        if ($reservationId === null) {
            return $this->restartWith($request, $reservation->attempt->message());
        }

        // Every reservation is settled within this request, exactly once: a
        // counted failure releases it through recordFailedLogin(), everything
        // else here. Its id stays in this request and is never sent to the
        // browser.
        $counted = false;
        $username = $request->string('username')->toString();
        $password = $request->string('password')->toString();
        $request->request->remove('password');
        try {
            if (! $budget->tryConsume()) {
                return $this->backToLoginForm($request, ['login' => self::MSG_BANK_BUSY]);
            }

            $jar = new CookieJar;
            try {
                $qr = $bank->startLogin($jar, $username, $password);
            } catch (BankException $exception) {
                $this->logBankFailure($exception);
                if (! $exception->failedCredentialSubmit) {
                    return $this->backToLoginForm($request, ['login' => $exception->failure->message()]);
                }

                // If the failure cannot be recorded the reservation is left
                // to expire: releasing it would turn a counted failure into
                // a free retry.
                $counted = true;

                return match ($this->recordFailedLogin($store, $codeHash, $reservationId)) {
                    true => $this->restartWith($request, CodeStatus::Locked->message()),
                    false => $this->backToLoginForm($request, ['login' => $exception->failure->message().' '.self::MSG_LOGIN_FAILED_WARNING]),
                    null => $this->backToLoginForm($request, ['login' => self::MSG_SERVICE_DOWN]),
                };
            }
        } finally {
            sodium_memzero($password);
            if (! $counted) {
                $this->endLoginAttempt($store, $codeHash, $reservationId);
            }
        }

        $flow->awaitApproval($webhookUrl, $jar, $qr);

        return redirect()->route('registration.approve');
    }

    public function showApproval(Request $request): View|RedirectResponse
    {
        $flow = $this->flow($request);
        $qr = $flow->qr();
        if ($flow->stage() !== Stage::AwaitingApproval || $qr === null) {
            return $this->redirectToStage($request, $flow);
        }

        return view('registration.approve', [
            'qrImage' => $qr->imageDataUri,
            'secondsLeft' => max(0, $qr->expiresAt - now()->getTimestamp()),
        ]);
    }

    public function approvalStatus(Request $request, KbizClient $bank, RegistrationStore $store): JsonResponse|RedirectResponse
    {
        $flow = $this->flow($request);
        $qr = $flow->qr();
        if ($flow->stage() !== Stage::AwaitingApproval || $qr === null) {
            return $this->pollResult($request, 'restart', $this->redirectToStage($request, $flow)->getTargetUrl());
        }

        if (now()->getTimestamp() >= $qr->expiresAt) {
            return $this->failApproval($request, $flow, 'expired', 'QR หมดอายุแล้ว กรุณาเข้าสู่ระบบอีกครั้งเพื่อรับ QR ใหม่');
        }

        $jar = $flow->bankCookies();
        try {
            $status = $bank->approvalStatus($jar);
            $flow->saveBankCookies($jar);

            if ($status === ApprovalStatus::Pending) {
                return $this->pollResult($request, 'pending');
            }
            if ($status === ApprovalStatus::Rejected) {
                return $this->rejectedApproval($request, $flow, $store);
            }

            $bankSession = $bank->completeLogin($jar);
            $flow->chooseAccounts($bankSession, $bank->listAccounts($jar, $bankSession));
        } catch (BankException $exception) {
            $this->logBankFailure($exception);

            return $this->failApproval($request, $flow, 'failed', $exception->failure->message());
        }

        return $this->pollResult($request, 'approved', route('registration.accounts'));
    }

    public function showAccounts(Request $request, Registrar $registrar, RegistrationStore $store): View|RedirectResponse
    {
        $flow = $this->flow($request);
        if ($flow->stage() !== Stage::ChoosingAccounts) {
            return $this->redirectToStage($request, $flow);
        }
        $accounts = $flow->accounts();
        $codeHash = $flow->codeHash();
        $bankSession = $flow->bankSession();
        if ($codeHash === null || $bankSession === null || $accounts === []) {
            return $this->restartWith($request, self::MSG_SESSION_EXPIRED);
        }

        // Every call spends the code's state budget, so a list is asked about
        // once; only a failed ask is repeated on the next view.
        $states = $flow->accountStates();
        if ($states === null) {
            try {
                $states = $registrar->accountStates($codeHash, $bankSession, $accounts);
                $flow->rememberAccountStates($states);
            } catch (RegistrationRejected $rejection) {
                if ($rejection->reason === RejectionReason::CodeUnusable) {
                    return $this->codeNoLongerUsable($request, $store, $codeHash);
                }
                if ($rejection->reason === RejectionReason::StatesBudgetExhausted) {
                    return $this->restartWith($request, CodeStatus::Exhausted->message());
                }
                Log::error('registration_account_states refused the account list', ['reason' => $rejection->reason->value]);
            } catch (RegistrationStoreUnavailable) {
                // Already logged by the store; nothing is selectable until a view succeeds.
            }
        }

        return view('registration.accounts', [
            'accounts' => $accounts,
            'states' => $states ?? [],
            'statesUnavailable' => $states === null,
            'notAskedNote' => self::MSG_NOT_ASKED,
            'listNonce' => $flow->listNonce(),
        ]);
    }

    public function submitAccounts(
        Request $request,
        Registrar $registrar,
        RegistrationStore $store,
        WrapbizSettings $settings,
    ): Response|RedirectResponse {
        $flow = $this->flow($request);
        $accounts = $flow->accounts();
        $codeHash = $flow->codeHash();
        $webhookUrl = $flow->webhookUrl();
        $bankSession = $flow->bankSession();
        $listNonce = $flow->listNonce();
        if ($flow->stage() !== Stage::ChoosingAccounts || $codeHash === null || $webhookUrl === null
            || $bankSession === null || $listNonce === null || $accounts === []
        ) {
            return $this->redirectToStage($request, $flow);
        }

        $submittedNonce = $request->input('list');
        if (! is_string($submittedNonce) || ! hash_equals($listNonce, $submittedNonce)) {
            return redirect()->route('registration.accounts')->withErrors(['account' => self::MSG_LIST_CHANGED]);
        }

        $request->validate(
            ['account' => ['required', 'string']],
            ['account.required' => self::MSG_CHOOSE_ACCOUNT, 'account.string' => self::MSG_INVALID_SELECTION],
        );

        $token = $request->string('account')->toString();
        if (! isset($accounts[$token])) {
            return $this->accountsError($request, self::MSG_INVALID_SELECTION);
        }
        $states = $flow->accountStates();
        if ($states === null) {
            return $this->accountsError($request, self::MSG_STATES_UNKNOWN);
        }
        $state = $states[$token] ?? null;
        if ($state === null) {
            return $this->accountsError($request, self::MSG_NOT_ASKED);
        }
        if (! $state->selectable()) {
            return $this->accountsError($request, (string) $state->note());
        }

        try {
            $results = $registrar->register($codeHash, $webhookUrl, $bankSession, $accounts[$token], (string) $request->ip());
        } catch (RegistrationRejected $rejection) {
            return match ($rejection->reason) {
                RejectionReason::CodeUnusable => $this->codeNoLongerUsable($request, $store, $codeHash),
                RejectionReason::UserAlreadyRegistered => $this->accountsChangedMeanwhile($flow, AccountState::MSG_USER_BOUND),
                RejectionReason::AccountAlreadyRegistered => $this->accountsChangedMeanwhile($flow, self::MSG_ALREADY_REGISTERED),
                RejectionReason::EndpointConflict => $this->accountsError($request, self::MSG_ENDPOINT_CONFLICT),
                RejectionReason::EndpointUrlLocked => $this->accountsError($request, self::MSG_ENDPOINT_URL_LOCKED),
                RejectionReason::EndpointDisabled => $this->accountsError($request, self::MSG_ENDPOINT_DISABLED),
                RejectionReason::InvalidAccounts => $this->accountsError($request, self::MSG_INVALID_SELECTION),
                RejectionReason::InvalidInput => $this->accountsError($request, self::MSG_INVALID_INPUT),
                RejectionReason::StatesBudgetExhausted => $this->restartWith($request, CodeStatus::Exhausted->message()),
            };
        } catch (RegistrationStoreUnavailable) {
            return $this->outcomeUnknown($request, $store, $codeHash);
        }

        $flow->clear();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->view('registration.success', [
            'results' => $results,
            'webhookUrl' => $webhookUrl,
            'signingKeys' => $settings->signingKeys,
            'phpSnippet' => $this->snippet('wrapbiz-verify.php'),
            'nodeSnippet' => $this->snippet('wrapbiz-verify.mjs'),
        ]);
    }

    public function restart(Request $request): RedirectResponse
    {
        $this->flow($request)->clear();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('registration.code');
    }

    private function flow(Request $request): RegistrationFlow
    {
        return new RegistrationFlow($request->session());
    }

    private function redirectToStage(Request $request, RegistrationFlow $flow): RedirectResponse
    {
        $stage = $flow->stage();

        return $stage === null
            ? $this->restartWith($request, self::MSG_SESSION_EXPIRED)
            : redirect()->route($stage->route());
    }

    private function restartWith(Request $request, string $message): RedirectResponse
    {
        $this->flow($request)->clear();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('registration.code')->withErrors(['code' => $message]);
    }

    /**
     * The register call was rejected because the code is no longer usable.
     * Which state it is in decides whether anything may have been saved.
     */
    private function codeNoLongerUsable(Request $request, RegistrationStore $store, string $codeHash): RedirectResponse
    {
        try {
            $status = $store->codeStatus($codeHash);
        } catch (RegistrationStoreUnavailable) {
            $status = CodeStatus::Used;
        }

        return $this->restartWith($request, $status === CodeStatus::Usable ? CodeStatus::Used->message() : $status->message());
    }

    /**
     * Another registration took the account, or bound this K BIZ user to
     * another one, after the list was asked about, so the remembered states
     * are stale: the next view asks again (spending one call of the code's
     * budget) and shows the account as not selectable.
     */
    private function accountsChangedMeanwhile(RegistrationFlow $flow, string $message): RedirectResponse
    {
        $flow->forgetAccountStates();

        return redirect()->route('registration.accounts')->withErrors(['account' => $message]);
    }

    /**
     * Back to the list with the choice kept, so the customer sees which
     * account the message is about.
     */
    private function accountsError(Request $request, string $message): RedirectResponse
    {
        return redirect()->route('registration.accounts')
            ->withInput($request->only('account'))
            ->withErrors(['account' => $message]);
    }

    /**
     * The register call failed without an answer, so it may or may not have
     * committed. Code consumption is part of the same transaction, so the
     * code's state tells which.
     */
    private function outcomeUnknown(Request $request, RegistrationStore $store, string $codeHash): RedirectResponse
    {
        try {
            $status = $store->codeStatus($codeHash);
        } catch (RegistrationStoreUnavailable) {
            return back()->withErrors(['account' => self::MSG_OUTCOME_UNKNOWN]);
        }

        // An exhausted code refuses new bank logins but still registers the
        // list already shown, so it is as unconsumed as a usable one.
        return $status === CodeStatus::Usable || $status === CodeStatus::Exhausted
            ? back()->withErrors(['account' => self::MSG_NOT_COMPLETED])
            : $this->restartWith($request, $status->message());
    }

    /**
     * A reservation that cannot be released expires on its own within
     * minutes, so the customer is not held up over it.
     */
    private function endLoginAttempt(RegistrationStore $store, string $codeHash, string $reservationId): void
    {
        try {
            $store->endLoginAttempt($codeHash, $reservationId);
        } catch (RegistrationStoreUnavailable) {
            Log::warning('could not release a register-code login attempt; it will expire');
        }
    }

    /**
     * @return ?bool true when the code is now locked; null when the failure could not be recorded
     */
    private function recordFailedLogin(RegistrationStore $store, string $codeHash, ?string $reservationId): ?bool
    {
        try {
            return $store->recordFailedLogin($codeHash, $reservationId);
        } catch (RegistrationStoreUnavailable) {
            return null;
        }
    }

    private function rejectedApproval(Request $request, RegistrationFlow $flow, RegistrationStore $store): JsonResponse|RedirectResponse
    {
        $codeHash = $flow->codeHash();
        // The login's reservation was released when the QR was shown.
        $locked = $codeHash === null ? null : $this->recordFailedLogin($store, $codeHash, null);
        if ($locked === true) {
            $this->flow($request)->clear();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            $request->session()->flash('errors', (new ViewErrorBag)->put('default', new MessageBag(['code' => CodeStatus::Locked->message()])));

            return $this->pollResult($request, 'locked', route('registration.code'), CodeStatus::Locked->message());
        }

        return $this->failApproval(
            $request,
            $flow,
            'rejected',
            'การเข้าสู่ระบบถูกปฏิเสธในแอป K BIZ กรุณาลองใหม่อีกครั้ง '.self::MSG_LOGIN_FAILED_WARNING,
        );
    }

    /**
     * @param  array<string, string>  $errors
     */
    private function backToLoginForm(Request $request, array $errors): RedirectResponse
    {
        return redirect()->route('registration.login')
            ->withInput($request->except(self::NEVER_FLASHED))
            ->withErrors($errors);
    }

    private function failApproval(Request $request, RegistrationFlow $flow, string $state, string $message): JsonResponse|RedirectResponse
    {
        $flow->backToLogin();
        $request->session()->flash('login_error', $message);

        return $this->pollResult($request, $state, route('registration.login'), $message);
    }

    /**
     * JSON for the polling script; a plain redirect for the no-JavaScript form.
     */
    private function pollResult(Request $request, string $state, ?string $redirect = null, ?string $message = null): JsonResponse|RedirectResponse
    {
        if (! $request->expectsJson()) {
            return redirect()->to($redirect ?? route('registration.approve'));
        }

        return response()->json(array_filter(
            ['state' => $state, 'redirect' => $redirect, 'message' => $message],
            fn (?string $value) => $value !== null,
        ));
    }

    private function logBankFailure(BankException $exception): void
    {
        Log::warning('KBiz bank step failed', [
            'step' => $exception->step,
            'failure' => $exception->failure->value,
            'failed_credential_submit' => $exception->failedCredentialSubmit,
        ]);
    }

    private function snippet(string $file): string
    {
        return (string) file_get_contents(resource_path('snippets/'.$file));
    }
}
