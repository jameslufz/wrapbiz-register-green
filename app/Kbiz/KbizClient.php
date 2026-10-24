<?php

namespace App\Kbiz;

use App\Security\AccountNumber;
use Closure;
use DOMDocument;
use DOMNodeList;
use DOMXPath;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\ConnectException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Drives the KBiz web login on the customer's behalf. Stateless: the caller
 * owns the bank cookie jar and passes it into every call.
 *
 * Every bank-specific string comes from KbizConfig; this class only uses
 * logical names.
 */
final readonly class KbizClient
{
    private const int MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

    private const int MAX_QR_IMAGE_BYTES = 512 * 1024;

    private const int DEFAULT_QR_LIFETIME_SECONDS = 180;

    private const int MAX_QR_LIFETIME_SECONDS = 900;

    private const string QR_IMAGE_TYPES = 'png|jpeg|gif|webp';

    private const int MAX_SESSION_VALUE_LENGTH = 4096;

    private const int MAX_ACCOUNT_KIND_BYTES = 256;

    /**
     * Repeating these could lock the bank user (credentials) or replay a
     * single-use hand-off, so they are sent exactly once.
     */
    private const array ONE_TIME_STEPS = ['login_submit', 'qr_confirm', 'bank_redirect', 'validate_session'];

    public const int CONNECT_ATTEMPTS = 3;

    public const int CONNECT_RETRY_DELAY_MS = 300;

    public const int MAX_CONNECT_TIMEOUT_SECONDS = 10;

    public function __construct(
        private KbizConfig $config,
        private HttpFactory $http,
    ) {}

    public function startLogin(
        CookieJar $jar,
        #[\SensitiveParameter] string $username,
        #[\SensitiveParameter] string $password,
    ): QrChallenge {
        $loginPage = $this->config->step('login_page');
        $loginToken = $this->xpathValue($this->get($loginPage, $jar)->body(), 'login_token')
            ?? throw new BankException(BankFailure::UnexpectedResponse, $loginPage->name);

        $submit = $this->config->step('login_submit');
        $form = [
            ...$submit->constantFields(),
            $submit->field('login_name') => $username,
            $submit->field('login_secret') => $password,
            $submit->field('login_token') => $loginToken,
        ];
        $html = $this->submitCredentials($submit, $jar, $form);
        unset($form);

        $imageSource = $this->xpathValue($html, 'qr_image');
        $deadline = $this->xpathValue($html, 'qr_deadline');
        if ($imageSource === null || $deadline === null) {
            throw new BankException(BankFailure::LoginFailed, $submit->name, failedCredentialSubmit: true);
        }

        return new QrChallenge(
            $this->inlineQrImage($imageSource, $jar, $submit),
            $this->parseDeadline($deadline),
        );
    }

    public function approvalStatus(CookieJar $jar): ApprovalStatus
    {
        $step = $this->config->step('approval_status');
        $status = data_get($this->postJson($step, $jar, [])->json(), $step->field('approval_state'));

        if (! is_string($status) || $status === '') {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        return match ($status) {
            $step->value('state_approved') => ApprovalStatus::Approved,
            $step->value('state_rejected') => ApprovalStatus::Rejected,
            default => ApprovalStatus::Pending,
        };
    }

    /**
     * Runs the post-approval hand-off and returns the logged-in bank session.
     */
    public function completeLogin(CookieJar $jar): BankSession
    {
        $confirm = $this->config->step('qr_confirm');
        $html = $this->postForm($confirm, $jar, [
            ...$confirm->constantFields(),
            $confirm->field('qr_timestamp') => (string) now()->getTimestampMs(),
        ])->body();
        if (preg_match($this->config->selector('qr_confirmed'), $html) !== 1) {
            throw new BankException(BankFailure::UnexpectedResponse, $confirm->name);
        }

        $redirect = $this->config->step('bank_redirect');
        $redirectHtml = $this->get($redirect, $jar)->body();
        if (preg_match($this->config->selector('handoff_token'), $redirectHtml, $matches) !== 1
            || ! self::isSessionValue(urldecode($matches[1] ?? ''))
        ) {
            throw new BankException(BankFailure::UnexpectedResponse, $redirect->name);
        }

        return $this->exchangeHandoffToken($jar, urldecode($matches[1]));
    }

    /**
     * @return list<BankAccount>
     */
    public function listAccounts(CookieJar $jar, BankSession $session): array
    {
        $step = $this->config->step('list_accounts');
        $response = $this->postJson($step, $jar, [
            ...$step->constantFields(),
            $step->field('customer_type') => $session->customerType,
            $step->field('owner_id') => $session->orgId,
        ], [
            $step->field('user_ref_header') => $session->userRef,
            $step->field('session_user_ref_header') => $session->userRef,
            $step->field('session_auth_header') => $session->sessionToken,
        ]);

        $rows = data_get($response->json(), $step->field('account_list'));
        if (! is_array($rows) || ! array_is_list($rows)) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        $accounts = [];
        foreach ($rows as $row) {
            $number = is_array($row) ? AccountNumber::tryFrom($row[$step->field('account_number')] ?? null) : null;
            if ($number === null || isset($accounts[$number->digits])) {
                continue;
            }
            $accounts[$number->digits] = new BankAccount($number, self::accountKind($row[$step->field('account_kind')] ?? null));
        }

        if ($accounts === []) {
            throw new BankException(BankFailure::NoAccounts, $step->name);
        }

        return array_values($accounts);
    }

    /**
     * Every answer the bank gives to a credential submission other than a QR
     * challenge counts against the register code (a 3xx/4xx/5xx may just as
     * well mean "wrong password"). Only failures where the bank never
     * answered do not.
     *
     * @param  array<string, string>  $form
     */
    private function submitCredentials(KbizStep $submit, CookieJar $jar, #[\SensitiveParameter] array $form): string
    {
        try {
            return $this->postForm($submit, $jar, $form)->body();
        } catch (BankException $exception) {
            if ($exception->failure === BankFailure::Unreachable) {
                throw $exception;
            }

            throw new BankException($exception->failure, $exception->step, failedCredentialSubmit: true);
        }
    }

    private function exchangeHandoffToken(CookieJar $jar, #[\SensitiveParameter] string $handoffToken): BankSession
    {
        $step = $this->config->step('validate_session');
        $response = $this->postJson($step, $jar, [
            $step->field('handoff_token') => $handoffToken,
        ]);

        $profile = data_get($response->json(), $step->field('profile'));
        $sessionToken = $response->header($step->field('session_token_header'));
        if (! is_array($profile) || ! self::isSessionValue($sessionToken)) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        $userRef = $profile[$step->field('user_ref')] ?? null;
        $orgId = $profile[$step->field('org_id')] ?? null;
        $customerType = $profile[$step->field('customer_type')] ?? '';
        if (! self::isSessionValue($userRef) || ! self::isSessionValue($orgId)
            || ! ($customerType === '' || self::isSessionValue($customerType))
        ) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        return new BankSession($sessionToken, $userRef, $orgId, $customerType);
    }

    /**
     * The worker's strict decoder refuses a sealed account whose type is not
     * a short, valid UTF-8 string, so anything else is dropped rather than
     * sealed.
     */
    private static function accountKind(mixed $kind): string
    {
        return is_string($kind)
            && strlen($kind) <= self::MAX_ACCOUNT_KIND_BYTES
            && mb_check_encoding($kind, 'UTF-8')
            && preg_match('/[\p{Cc}\x{FFFD}]/u', $kind) === 0
            ? $kind
            : '';
    }

    /**
     * Values the worker will replay to the bank later: printable ASCII only,
     * so they survive JSON sealing and header injection is impossible.
     */
    private static function isSessionValue(mixed $value): bool
    {
        return is_string($value)
            && strlen($value) <= self::MAX_SESSION_VALUE_LENGTH
            && preg_match('/^[\x21-\x7E]+$/D', $value) === 1;
    }

    /**
     * Returns the QR as a data URI so the browser never contacts the bank.
     */
    private function inlineQrImage(string $source, CookieJar $jar, KbizStep $step): string
    {
        $pattern = '#^data:image/('.self::QR_IMAGE_TYPES.');base64,([A-Za-z0-9+/=\s]+)$#D';
        if (preg_match($pattern, $source, $matches) === 1) {
            $bytes = base64_decode(preg_replace('/\s+/', '', $matches[2]) ?? '', true);
            if ($bytes === false || $bytes === '' || strlen($bytes) > self::MAX_QR_IMAGE_BYTES) {
                throw new BankException(BankFailure::UnexpectedResponse, $step->name);
            }

            return "data:image/{$matches[1]};base64,".base64_encode($bytes);
        }

        $url = $this->resolveBankUrl($source, $step);
        $response = $this->send($step, $jar, fn (PendingRequest $request) => $request->get($url), retry: true);
        $contentType = strtolower(trim(explode(';', $response->header('Content-Type'))[0]));
        $bytes = $response->body();
        if (preg_match('#^image/('.self::QR_IMAGE_TYPES.')$#D', $contentType) !== 1
            || $bytes === '' || strlen($bytes) > self::MAX_QR_IMAGE_BYTES
        ) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        return "data:{$contentType};base64,".base64_encode($bytes);
    }

    /**
     * Only URLs on the configured bank origin are followed.
     */
    private function resolveBankUrl(string $source, KbizStep $step): string
    {
        $source = trim($source);
        if (str_starts_with($source, 'https://')) {
            $parts = parse_url($source);
            if ($parts === false || strtolower($parts['host'] ?? '') !== $this->config->host
                || isset($parts['user']) || isset($parts['port'])
            ) {
                throw new BankException(BankFailure::UnexpectedResponse, $step->name);
            }

            return $source;
        }

        if ($source === '' || str_starts_with($source, '//') || preg_match('#^[a-z][a-z0-9+.-]*:#i', $source) === 1) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        if (str_starts_with($source, '/')) {
            return $this->config->baseUrl.$source;
        }

        $directory = rtrim(dirname($step->path), '/');

        return $this->config->baseUrl.$directory.'/'.$source;
    }

    /**
     * The bank's QR timeout may be an epoch deadline (seconds or ms) or a
     * remaining duration (seconds or ms). Implausible values fall back to a
     * short default lifetime.
     */
    private function parseDeadline(string $raw): int
    {
        $now = now()->getTimestamp();
        if (preg_match('/^\d{1,16}$/D', $raw) !== 1) {
            return $now + self::DEFAULT_QR_LIFETIME_SECONDS;
        }

        $value = (int) $raw;
        $deadline = match (true) {
            $value <= 3_600 => $now + $value,
            $value < 1_000_000_000 => $now + intdiv($value, 1000),
            $value < 1_000_000_000_000 => $value,
            default => intdiv($value, 1000),
        };

        return $deadline > $now && $deadline <= $now + self::MAX_QR_LIFETIME_SECONDS
            ? $deadline
            : $now + self::DEFAULT_QR_LIFETIME_SECONDS;
    }

    private function xpathValue(string $html, string $selectorName): ?string
    {
        if (trim($html) === '') {
            return null;
        }

        $document = new DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $loaded = $document->loadHTML($html, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        if (! $loaded) {
            return null;
        }

        $result = (new DOMXPath($document))->evaluate($this->config->selector($selectorName));
        $value = match (true) {
            $result instanceof DOMNodeList => $result->item(0)?->nodeValue,
            is_string($result) => $result,
            default => null,
        };
        $value = $value === null ? '' : trim($value);

        return $value === '' ? null : $value;
    }

    private function get(KbizStep $step, CookieJar $jar): Response
    {
        return $this->send($step, $jar, fn (PendingRequest $request) => $request->get($this->config->url($step)));
    }

    /**
     * @param  array<string, string>  $form
     */
    private function postForm(KbizStep $step, CookieJar $jar, #[\SensitiveParameter] array $form): Response
    {
        return $this->send(
            $step,
            $jar,
            fn (PendingRequest $request) => $request->asForm()->post($this->config->url($step), $form),
        );
    }

    /**
     * Payloads are always encoded as a JSON object: an empty PHP array would
     * otherwise become "[]".
     *
     * @param  array<string, string>  $payload
     * @param  array<string, string>  $headers
     */
    private function postJson(
        KbizStep $step,
        CookieJar $jar,
        #[\SensitiveParameter] array $payload,
        #[\SensitiveParameter] array $headers = [],
    ): Response {
        $body = json_encode((object) $payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $response = $this->send(
            $step,
            $jar,
            fn (PendingRequest $request) => $request
                ->withHeaders($headers)
                ->withBody($body, 'application/json')
                ->post($this->config->url($step)),
        );

        if (! is_array($response->json())) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        return $response;
    }

    /**
     * Sends one bank request. Redirects are never followed (a 3xx is an
     * error), the body is capped while it streams, and only failures to
     * establish a connection are retried, never for one-time steps.
     *
     * @param  Closure(PendingRequest): Response  $perform
     */
    private function send(KbizStep $step, CookieJar $jar, Closure $perform, ?bool $retry = null): Response
    {
        $sink = new BoundedSink(self::MAX_RESPONSE_BYTES);
        $request = $this->http
            ->withOptions([
                'cookies' => $jar,
                'allow_redirects' => false,
                'sink' => $sink->stream(),
                'on_headers' => fn (ResponseInterface $response) => $sink->checkDeclaredLength($response->getHeaderLine('Content-Length')),
            ])
            ->timeout($this->config->timeoutSeconds)
            ->connectTimeout(min(self::MAX_CONNECT_TIMEOUT_SECONDS, $this->config->timeoutSeconds))
            ->withHeaders($step->headers);

        if ($retry ?? ! in_array($step->name, self::ONE_TIME_STEPS, true)) {
            $request = $request->retry(
                self::CONNECT_ATTEMPTS,
                self::CONNECT_RETRY_DELAY_MS,
                fn (?Throwable $exception) => self::neverReachedTheBank($exception),
                throw: false,
            );
        }

        try {
            $response = $perform($request);
        } catch (ConnectionException) {
            throw new BankException($sink->exceeded() ? BankFailure::UnexpectedResponse : BankFailure::Unreachable, $step->name);
        } catch (RequestException) {
            throw new BankException(BankFailure::HttpError, $step->name);
        }

        if ($response->redirect()) {
            throw new BankException(BankFailure::Redirected, $step->name);
        }
        if (! $response->successful()) {
            throw new BankException(BankFailure::HttpError, $step->name);
        }
        if ($sink->exceeded() || strlen($response->body()) > self::MAX_RESPONSE_BYTES) {
            throw new BankException(BankFailure::UnexpectedResponse, $step->name);
        }

        return $response;
    }

    /**
     * True only when the TCP/TLS connection was never established, so the
     * request cannot have reached the bank.
     */
    private static function neverReachedTheBank(?Throwable $exception): bool
    {
        return $exception instanceof ConnectionException
            && $exception->getPrevious() instanceof ConnectException;
    }
}
