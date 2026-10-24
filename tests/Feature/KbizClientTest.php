<?php

namespace Tests\Feature;

use App\Kbiz\ApprovalStatus;
use App\Kbiz\BankException;
use App\Kbiz\BankFailure;
use App\Kbiz\BankSession;
use App\Kbiz\KbizClient;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ConnectTimeoutException;
use GuzzleHttp\Exception\NetworkTimeoutException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeBank;
use Tests\TestCase;

final class KbizClientTest extends TestCase
{
    private function client(): KbizClient
    {
        return $this->app->make(KbizClient::class);
    }

    public function test_full_flow_against_env_described_bank(): void
    {
        Date::setTestNow('2026-10-16 10:00:00');
        FakeBank::fake();
        $jar = new CookieJar;
        $client = $this->client();

        $qr = $client->startLogin($jar, 'alice', 'p@ss-word');
        $this->assertSame('data:image/png;base64,'.FakeBank::QR_PNG_BASE64, $qr->imageDataUri);
        $this->assertSame(now()->getTimestamp() + 120, $qr->expiresAt);

        $this->assertSame(ApprovalStatus::Approved, $client->approvalStatus($jar));

        $session = $client->completeLogin($jar);
        $this->assertSame('session-token-xyz', $session->sessionToken);
        $this->assertSame('U-1', $session->userRef);
        $this->assertSame('ORG-9', $session->orgId);
        $this->assertSame('C', $session->customerType);

        $accounts = $client->listAccounts($jar, $session);
        $this->assertSame(['1234567890', '0987654321'], array_map(fn ($a) => $a->number->digits, $accounts));
        $this->assertSame(['SA', 'CA'], array_map(fn ($a) => $a->kind, $accounts));

        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit')
            && $r->method() === 'POST'
            && $r->isForm()
            && $r->data() === ['k_cmd' => 'go', 'k_locale' => 'xx', 'k_ctype' => 'ct-x', 'k_touch' => '7', 'k_app' => '9',
                'k_user' => 'alice', 'k_pass' => 'p@ss-word', 'k_token' => 'tok-123']
            && $r->header('X-Test-Agent') === ['test-agent']);

        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/three') && $r->body() === '{}');

        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/four')
            && $r->data() === ['k_err' => 'err-x', 'k_locale' => 'xx', 'k_cmd' => 'go', 'k_ts' => (string) now()->getTimestampMs()]);

        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/six') && $r->data() === ['k_handoff' => 'hand-off']);

        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/seven')
            && $r->data() === ['k_filter' => 'A,B', 'k_bal' => 'bal-x', 'k_lang' => 'xx', 'k_nick' => 'nick', 'k_okind' => 'org', 'k_ctype' => 'C', 'k_owner' => 'ORG-9']
            && $r->header('x-test-auth') === ['session-token-xyz']
            && $r->header('x-test-uref') === ['U-1']
            && $r->header('x-test-suref') === ['U-1']
            && $r->header('x-test-app') === ['tester']);

        Http::assertSentCount(7);
    }

    public function test_password_is_only_sent_to_the_login_submit_step(): void
    {
        FakeBank::fake();
        $jar = new CookieJar;
        $client = $this->client();

        $client->startLogin($jar, 'alice', 'UNIQUE-PASSWORD-91');
        $client->approvalStatus($jar);
        $client->listAccounts($jar, $client->completeLogin($jar));

        $recorded = Http::recorded();
        $carrying = $recorded->filter(fn (array $pair) => str_contains($pair[0]->body(), 'UNIQUE-PASSWORD-91'));
        $this->assertCount(1, $carrying);
        $this->assertTrue(FakeBank::sentTo($carrying->first()[0], '/p/two/submit'));
        $this->assertStringNotContainsString('UNIQUE-PASSWORD-91', json_encode($jar->toArray()));
    }

    public function test_bank_cookies_are_kept_in_the_caller_jar(): void
    {
        FakeBank::fake();
        $jar = new CookieJar;

        $this->client()->startLogin($jar, 'alice', 'pw');

        $this->assertSame('abc', $jar->getCookieByName('BANKSID')?->getValue());
        Http::assertSent(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit') && str_contains($r->header('Cookie')[0] ?? '', 'BANKSID=abc'));
    }

    public function test_missing_login_token_is_an_unexpected_response(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => Http::response('<html><body>maintenance</body></html>')]);

        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'login_page', fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));
        Http::assertNotSent(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'));
    }

    public function test_login_page_without_qr_means_login_failed(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<html><body>wrong password</body></html>')]);

        $this->assertBankFailure(BankFailure::LoginFailed, 'login_submit', fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));
    }

    public function test_login_submit_is_never_retried_even_when_the_connection_failed(): void
    {
        $submits = 0;
        Http::fake(function (Request $request) use (&$submits) {
            if (FakeBank::sentTo($request, '/p/one')) {
                return Http::response(FakeBank::loginPage());
            }
            $submits++;

            return self::rejectWith(ConnectException::class, $request, 'cURL error 7: secret detail');
        });

        $exception = $this->assertBankFailure(BankFailure::Unreachable, 'login_submit', fn () => $this->client()->startLogin(new CookieJar, 'a', 'secret-pw'));
        $this->assertSame(1, $submits);
        $this->assertNull($exception->getPrevious());
        $this->assertStringNotContainsString('secret', $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string, callable(KbizClient): mixed}>
     */
    public static function oneTimeSteps(): iterable
    {
        yield 'qr confirm' => ['/p/four', 'qr_confirm', fn (KbizClient $client) => $client->completeLogin(new CookieJar)];
        yield 'hand-off page' => ['/p/five', 'bank_redirect', fn (KbizClient $client) => $client->completeLogin(new CookieJar)];
        yield 'validate session' => ['/p/six', 'validate_session', fn (KbizClient $client) => $client->completeLogin(new CookieJar)];
    }

    #[DataProvider('oneTimeSteps')]
    public function test_one_time_steps_are_sent_exactly_once(string $path, string $step, callable $call): void
    {
        FakeBank::fake();
        $attempts = 0;
        Http::fake(function (Request $request) use ($path, &$attempts) {
            if (! FakeBank::sentTo($request, $path)) {
                return null;
            }
            $attempts++;

            return self::rejectWith(ConnectTimeoutException::class, $request, 'connect timed out');
        });

        $this->assertBankFailure(BankFailure::Unreachable, $step, fn () => $call($this->client()));
        $this->assertSame(1, $attempts);
    }

    public function test_failed_connections_on_repeatable_steps_are_retried(): void
    {
        $calls = 0;
        Http::fake(function (Request $request) use (&$calls) {
            $calls++;
            if ($calls < 3) {
                return self::rejectWith(ConnectException::class, $request, 'cURL error 35: TLS handshake');
            }

            return Http::response(['k_wrap' => ['k_state' => 'WAIT']]);
        });

        $this->assertSame(ApprovalStatus::Pending, $this->client()->approvalStatus(new CookieJar));
        $this->assertSame(3, $calls);
    }

    public function test_timeouts_after_the_request_was_sent_are_not_retried(): void
    {
        $calls = 0;
        Http::fake(function (Request $request) use (&$calls) {
            $calls++;

            return self::rejectWith(NetworkTimeoutException::class, $request, 'cURL error 28: Operation timed out');
        });

        $this->assertBankFailure(BankFailure::Unreachable, 'approval_status', fn () => $this->client()->approvalStatus(new CookieJar));
        $this->assertSame(1, $calls);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function redirectStatuses(): iterable
    {
        foreach ([301, 302, 303, 307, 308] as $status) {
            yield (string) $status => [$status];
        }
    }

    #[DataProvider('redirectStatuses')]
    public function test_bug_001_redirects_are_never_followed(int $status): void
    {
        FakeBank::fake([
            FakeBank::BASE_URL.'/p/seven' => Http::response('', $status, ['Location' => 'https://evil.test/acc']),
            FakeBank::BASE_URL.'/p/two/submit' => Http::response('', $status, ['Location' => FakeBank::BASE_URL.'/p/one']),
        ]);

        $this->assertBankFailure(BankFailure::Redirected, 'list_accounts', fn () => $this->client()->listAccounts(new CookieJar, new BankSession('SESSION-TOKEN-SECRET', 'U', 'O', 'C')));
        $this->assertBankFailure(BankFailure::Redirected, 'login_submit', fn () => $this->client()->startLogin(new CookieJar, 'alice', 'pw'));

        Http::assertNotSent(fn (Request $r) => str_contains($r->url(), 'evil.test'));
        $this->assertSame(1, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/seven'))->count());
        $this->assertSame(1, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/one'))->count(), 'redirect back to the login page not followed');
    }

    public function test_http_errors_are_not_retried_and_hide_the_body(): void
    {
        Http::fake([FakeBank::BASE_URL.'/p/three' => Http::response('internal detail trace-ref=123', 500)]);

        $exception = $this->assertBankFailure(BankFailure::HttpError, 'approval_status', fn () => $this->client()->approvalStatus(new CookieJar));
        Http::assertSentCount(1);
        $this->assertStringNotContainsString('trace-ref', $exception->getMessage());
        $this->assertNull($exception->getPrevious());
    }

    public function test_approval_states(): void
    {
        Http::fakeSequence(FakeBank::BASE_URL.'/p/three')
            ->push(['k_wrap' => ['k_state' => 'WAIT']])
            ->push(['k_wrap' => ['k_state' => 'NO']])
            ->push(['k_wrap' => ['k_state' => 'YES']])
            ->push(['k_wrap' => []])
            ->push('not json');
        $client = $this->client();

        $this->assertSame(ApprovalStatus::Pending, $client->approvalStatus(new CookieJar));
        $this->assertSame(ApprovalStatus::Rejected, $client->approvalStatus(new CookieJar));
        $this->assertSame(ApprovalStatus::Approved, $client->approvalStatus(new CookieJar));
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'approval_status', fn () => $client->approvalStatus(new CookieJar));
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'approval_status', fn () => $client->approvalStatus(new CookieJar));
    }

    public function test_qr_confirmation_must_match_the_selector(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/four' => Http::response('<p>session expired</p>')]);

        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'qr_confirm', fn () => $this->client()->completeLogin(new CookieJar));
    }

    public function test_missing_handoff_token(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/five' => Http::response('<p>nothing</p>')]);

        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'bank_redirect', fn () => $this->client()->completeLogin(new CookieJar));
    }

    /**
     * @return iterable<string, array{string, mixed, mixed}>
     */
    public static function unprintableSessionValues(): iterable
    {
        yield 'non-utf8 token' => ['token', "tok\xff\xfe", 'U-1'];
        yield 'token with space' => ['token', 'tok en', 'U-1'];
        yield 'token too long' => ['token', str_repeat('t', 4097), 'U-1'];
        yield 'user ref with newline' => ['uref', 'tok', "U\n1"];
        yield 'user ref not a string' => ['uref', 'tok', 12345];
        yield 'user ref thai' => ['uref', 'tok', 'ผู้ใช้'];
    }

    #[DataProvider('unprintableSessionValues')]
    public function test_bug_005_session_values_must_be_printable_ascii(string $case, mixed $token, mixed $userRef): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/six' => Http::response(
            ['k_data' => ['k_profiles' => [['k_uref' => $userRef, 'k_org' => 'ORG-9', 'k_ctype' => 'C']]]],
            200,
            ['x-test-session' => $token],
        )]);

        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'validate_session', fn () => $this->client()->completeLogin(new CookieJar));
    }

    public function test_bug_005_handoff_token_must_be_printable_ascii(): void
    {
        foreach (['hand%00off', 'hand%0Aoff', 'hand%FFoff', '%20'] as $encoded) {
            FakeBank::fake([FakeBank::BASE_URL.'/p/five' => Http::response('<script>go("?k_handoff='.$encoded.'")</script>')]);

            $this->assertBankFailure(BankFailure::UnexpectedResponse, 'bank_redirect', fn () => $this->client()->completeLogin(new CookieJar));
            Http::assertNotSent(fn (Request $r) => FakeBank::sentTo($r, '/p/six'));
        }
    }

    public function test_empty_customer_type_is_allowed(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/six' => Http::response(
            ['k_data' => ['k_profiles' => [['k_uref' => 'U-1', 'k_org' => 'ORG-9']]]],
            200,
            ['x-test-session' => 'tok'],
        )]);

        $this->assertSame('', $this->client()->completeLogin(new CookieJar)->customerType);
    }

    public function test_session_requires_token_header_and_profile(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/six' => Http::response(['k_data' => ['k_profiles' => [['k_uref' => 'U', 'k_org' => 'O']]]])]);
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'validate_session', fn () => $this->client()->completeLogin(new CookieJar));

        FakeBank::fake([FakeBank::BASE_URL.'/p/six' => Http::response(['k_data' => ['k_profiles' => []]], 200, ['x-test-session' => 't'])]);
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'validate_session', fn () => $this->client()->completeLogin(new CookieJar));
    }

    public function test_account_list_edge_cases(): void
    {
        $session = new BankSession('t', 'u', 'o', 'c');

        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => []]])]);
        $this->assertBankFailure(BankFailure::NoAccounts, 'list_accounts', fn () => $this->client()->listAccounts(new CookieJar, $session));

        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => [['k_no' => 'abc'], 'junk']]])]);
        $this->assertBankFailure(BankFailure::NoAccounts, 'list_accounts', fn () => $this->client()->listAccounts(new CookieJar, $session));

        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => ['a' => 'b']]])]);
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'list_accounts', fn () => $this->client()->listAccounts(new CookieJar, $session));
    }

    /** The worker's strict decoder only opens account secrets with a short, valid string type. */
    public function test_account_kinds_the_worker_could_not_decode_are_dropped(): void
    {
        $kinds = ['ออมทรัพย์', "S\nA", "bad\u{FFFD}", str_repeat('k', 257), str_repeat('k', 256), 123, null, ['SA']];
        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => array_map(
            fn (mixed $kind, int $i) => ['k_no' => sprintf('10000000%02d', $i), 'k_kind' => $kind],
            $kinds,
            array_keys($kinds),
        )]])]);

        $accounts = $this->client()->listAccounts(new CookieJar, new BankSession('t', 'u', 'o', 'c'));

        $this->assertSame(['ออมทรัพย์', '', '', '', str_repeat('k', 256), '', '', ''], array_map(fn ($a) => $a->kind, $accounts));
    }

    public function test_relative_qr_image_is_fetched_with_the_jar_and_inlined(): void
    {
        $png = base64_decode(FakeBank::QR_PNG_BASE64);
        FakeBank::fake([
            FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('/img/qr?id=1')),
            FakeBank::BASE_URL.'/img/qr*' => Http::response($png, 200, ['Content-Type' => 'image/png']),
        ]);

        $qr = $this->client()->startLogin(new CookieJar, 'a', 'b');

        $this->assertSame('data:image/png;base64,'.base64_encode($png), $qr->imageDataUri);
        Http::assertSent(fn (Request $r) => $r->url() === FakeBank::BASE_URL.'/img/qr?id=1' && str_contains($r->header('Cookie')[0] ?? '', 'BANKSID=abc'));
    }

    public function test_qr_image_resolution_relative_to_step_directory(): void
    {
        FakeBank::fake([
            FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('qr.png')),
            FakeBank::BASE_URL.'/p/two/qr.png' => Http::response('GIF89a', 200, ['Content-Type' => 'image/gif; charset=binary']),
        ]);

        $this->assertSame('data:image/gif;base64,'.base64_encode('GIF89a'), $this->client()->startLogin(new CookieJar, 'a', 'b')->imageDataUri);
    }

    public function test_qr_image_must_be_on_the_bank_origin_and_an_image(): void
    {
        foreach (['https://evil.test/qr.png', '//evil.test/qr.png', 'javascript:alert(1)', 'data:text/html;base64,PHNjcmlwdD4='] as $source) {
            FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage($source))]);
            $this->assertBankFailure(BankFailure::UnexpectedResponse, 'login_submit', fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));
        }
        Http::assertNotSent(fn (Request $r) => str_contains($r->url(), 'evil.test'));

        FakeBank::fake([
            FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('/img/qr')),
            FakeBank::BASE_URL.'/img/qr' => Http::response('<svg onload=alert(1)>', 200, ['Content-Type' => 'image/svg+xml']),
        ]);
        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'login_submit', fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));
    }

    /**
     * @return iterable<string, array{\Closure(): array<string, mixed>, BankFailure, string, bool}>
     */
    public static function credentialSubmitOutcomes(): iterable
    {
        $unreachable = fn (Request $request) => self::rejectWith(ConnectException::class, $request, 'cURL error 7');
        $timedOut = fn (Request $request) => self::rejectWith(NetworkTimeoutException::class, $request, 'cURL error 28');

        yield 'no QR in the answer' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>wrong</p>')], BankFailure::LoginFailed, 'login_submit', true];
        yield '302' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response('', 302, ['Location' => '/x'])], BankFailure::Redirected, 'login_submit', true];
        yield '401' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response('', 401)], BankFailure::HttpError, 'login_submit', true];
        yield '500' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response('', 500)], BankFailure::HttpError, 'login_submit', true];
        yield 'oversized answer' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response(str_repeat('A', 3 * 1024 * 1024))], BankFailure::UnexpectedResponse, 'login_submit', true];
        yield 'submit never connected' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => $unreachable], BankFailure::Unreachable, 'login_submit', false];
        yield 'submit timed out' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => $timedOut], BankFailure::Unreachable, 'login_submit', false];
        yield 'login page failed' => [fn () => [FakeBank::BASE_URL.'/p/one' => Http::response('', 503)], BankFailure::HttpError, 'login_page', false];
        yield 'QR image unusable after the credentials were accepted' => [fn () => [
            FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('/img/qr')),
            FakeBank::BASE_URL.'/img/qr' => Http::response('', 500),
        ], BankFailure::HttpError, 'login_submit', false];
    }

    /**
     * @param  \Closure(): array<string, mixed>  $fakes
     */
    #[DataProvider('credentialSubmitOutcomes')]
    public function test_only_answers_to_the_credentials_are_flagged_as_failed_submits(\Closure $fakes, BankFailure $failure, string $step, bool $counted): void
    {
        FakeBank::fake($fakes());

        $exception = $this->assertBankFailure($failure, $step, fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));

        $this->assertSame($counted, $exception->failedCredentialSubmit);
    }

    public function test_qr_deadline_formats(): void
    {
        Date::setTestNow('2026-10-16 10:00:00');
        $now = now()->getTimestamp();
        $cases = [
            '90' => $now + 90,                                  // duration, seconds
            '120000' => $now + 120,                             // duration, milliseconds
            (string) ($now + 200) => $now + 200,                // epoch seconds
            (string) (($now + 300) * 1000) => $now + 300,       // epoch milliseconds
            (string) ($now - 10) => $now + 180,                 // past: default
            (string) ($now + 86_400) => $now + 180,             // too far: default
            'soon' => $now + 180,                               // garbage: default
            '0' => $now + 180,
        ];

        foreach ($cases as $raw => $expected) {
            FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage(null, (string) $raw))]);
            $this->assertSame($expected, $this->client()->startLogin(new CookieJar, 'a', 'b')->expiresAt, "deadline {$raw}");
        }
    }

    public function test_oversized_responses_are_rejected(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => Http::response(str_repeat('a', 2 * 1024 * 1024 + 1))]);

        $this->assertBankFailure(BankFailure::UnexpectedResponse, 'login_page', fn () => $this->client()->startLogin(new CookieJar, 'a', 'b'));
    }

    public function test_password_never_appears_in_the_exception_trace(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('nope', 503)]);

        try {
            $this->client()->startLogin(new CookieJar, 'alice', 'TRACE-PASSWORD-77');
            $this->fail('expected BankException');
        } catch (BankException $exception) {
            $this->assertStringNotContainsString('TRACE-PASSWORD-77', $exception->getMessage());
            $this->assertStringNotContainsString('TRACE-PASSWORD-77', $exception->getTraceAsString());
            $this->assertStringNotContainsString('TRACE-PASSWORD-77', print_r($exception->getTrace(), true));
        }
    }

    /**
     * @param  class-string<ConnectException|NetworkTimeoutException>  $class
     */
    private static function rejectWith(string $class, Request $request, string $message): PromiseInterface
    {
        return Create::rejectionFor(new $class($message, new PsrRequest($request->method(), $request->url())));
    }

    private function assertBankFailure(BankFailure $failure, string $step, callable $call): BankException
    {
        try {
            $call();
        } catch (BankException $exception) {
            $this->assertSame($failure, $exception->failure);
            $this->assertSame($step, $exception->step);

            return $exception;
        }

        $this->fail("expected BankException {$failure->value} at {$step}");
    }
}
