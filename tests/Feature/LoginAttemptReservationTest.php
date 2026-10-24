<?php

namespace Tests\Feature;

use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\LoginAttempt;
use App\Wrapbiz\RegistrationStore;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ViewErrorBag;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Support\FakeBank;
use Tests\Support\RecordingStore;
use Tests\TestCase;

/**
 * SEC-R2-01: every bank login holds one of the code's attempt slots from
 * before the bank is contacted until its outcome is known, so parallel
 * requests can never send more than LOCK_AFTER credential submissions.
 */
final class LoginAttemptReservationTest extends TestCase
{
    private const string CODE = 'reg-code-0123456789abcdef';

    private const string MSG_BUSY = 'มีการเข้าสู่ระบบด้วยรหัสนี้ค้างอยู่ กรุณารอสักครู่แล้วลองใหม่';

    private RecordingStore $store;

    private string $codeHash;

    /** @var list<string> */
    private array $logLines = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new RecordingStore([self::CODE]);
        $this->codeHash = hash('sha256', self::CODE, true);
        $this->app->instance(RegistrationStore::class, $this->store);
        Log::listen(function ($message) {
            $this->logLines[] = $message->message;
        });
    }

    public function test_a_shown_qr_releases_the_reservation(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);

        $this->login()->assertRedirect('/approve');

        $this->assertSame(['begin:ok', 'end:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(0, $this->store->inFlight[$this->codeHash]);
    }

    public function test_a_counted_failure_is_recorded_and_never_also_released(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);

        $this->login()->assertRedirect('/login');

        $this->assertSame(['begin:ok', 'record:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(0, $this->store->inFlight[$this->codeHash]);
        $this->assertSame(1, $this->store->failedLogins[$this->codeHash]);
    }

    public function test_a_rejected_approval_counts_without_releasing_any_reservation(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/three' => Http::response(['k_wrap' => ['k_state' => 'NO']])]);
        $this->post('/code', ['code' => self::CODE]);
        $this->login()->assertRedirect('/approve');
        $this->store->inFlight[$this->codeHash] = 1;

        $this->postJson('/approve/status')->assertJson(['state' => 'rejected']);

        $this->assertSame(['begin:ok', 'end:'.$this->store->lastReservationId, 'record:null'], $this->store->attemptLog);
        $this->assertSame(1, $this->store->inFlight[$this->codeHash], "another request's reservation is untouched");
        $this->assertSame(1, $this->store->failedLogins[$this->codeHash]);
    }

    public function test_the_reservation_id_never_reaches_the_browser_or_the_session(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);

        $response = $this->login();

        $this->assertNotNull($this->store->lastReservationId);
        $this->assertStringNotContainsString($this->store->lastReservationId, (string) $response->getContent());
        $this->assertStringNotContainsString($this->store->lastReservationId, json_encode(session()->all(), JSON_THROW_ON_ERROR));
        $this->assertStringNotContainsString($this->store->lastReservationId, (string) $this->get('/approve')->getContent());
    }

    public function test_a_reservation_id_sent_by_the_client_is_ignored(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);
        $foreign = '00000000-0000-4000-8000-999999999999';
        $this->store->reservations[$foreign] = $this->codeHash;

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])->from('/login')->post('/login', [
            'username' => 'alice', 'password' => 'pw', 'webhook_url' => 'https://hooks.example.com/wrapbiz',
            'reservation_id' => $foreign, 'registration' => ['reservation_id' => $foreign],
        ]);

        $this->assertSame(['begin:ok', 'record:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertArrayHasKey($foreign, $this->store->reservations);
    }

    /**
     * @return iterable<string, array{\Closure(): array<string, mixed>}>
     */
    public static function uncountedOutcomes(): iterable
    {
        $unreachable = fn (Request $request) => Create::rejectionFor(new ConnectException('cURL error 28', new PsrRequest('POST', $request->url())));

        yield 'login page down' => [fn () => [FakeBank::BASE_URL.'/p/one' => Http::response('down', 503)]];
        yield 'credential submit never connected' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => $unreachable]];
        yield 'QR image unusable' => [fn () => [FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('javascript:alert(1)'))]];
    }

    /**
     * @param  \Closure(): array<string, mixed>  $fake
     */
    #[DataProvider('uncountedOutcomes')]
    public function test_an_uncounted_outcome_releases_the_reservation(\Closure $fake): void
    {
        FakeBank::fake($fake());
        $this->post('/code', ['code' => self::CODE]);

        $this->login()->assertRedirect('/login');

        $this->assertSame(['begin:ok', 'end:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(0, $this->store->inFlight[$this->codeHash]);
        $this->assertSame([], $this->store->failedLogins);
    }

    public function test_a_refused_bank_budget_releases_the_reservation_without_contacting_the_bank(): void
    {
        config(['wrapbiz.bank_logins_per_minute' => '1']);
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => Http::response('down', 503)]);
        $this->post('/code', ['code' => self::CODE]);
        $this->login('198.51.100.1');
        $this->store->attemptLog = [];

        $this->login('198.51.100.2')->assertSessionHasErrors(['login' => 'มีผู้ใช้งานเข้าสู่ระบบธนาคารพร้อมกันจำนวนมาก กรุณารอสักครู่แล้วลองใหม่']);

        $this->assertSame(['begin:ok', 'end:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(0, $this->store->inFlight[$this->codeHash]);
        $this->assertSame(1, Http::recorded()->count());
    }

    public function test_an_unexpected_error_still_releases_the_reservation(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => fn () => throw new RuntimeException('boom')]);
        $this->post('/code', ['code' => self::CODE]);

        $this->login()->assertStatus(500);

        $this->assertSame(['begin:ok', 'end:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(0, $this->store->inFlight[$this->codeHash]);
    }

    public function test_a_busy_code_waits_without_contacting_the_bank_and_keeps_the_session(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->failedLogins[$this->codeHash] = 3;
        $this->store->inFlight[$this->codeHash] = 2;

        $this->login()->assertRedirect('/login');

        $this->assertSame(self::MSG_BUSY, $this->sessionError('login'));
        $this->assertSame('code_accepted', session('registration.stage'));
        $this->assertSame(['begin:busy'], $this->store->attemptLog);
        $this->assertSame(2, $this->store->inFlight[$this->codeHash]);
        Http::assertNothingSent();
    }

    /**
     * @return iterable<string, array{CodeStatus}>
     */
    public static function unusableCodes(): iterable
    {
        foreach ([CodeStatus::Unknown, CodeStatus::Used, CodeStatus::Expired, CodeStatus::Locked] as $status) {
            yield $status->value => [$status];
        }
    }

    #[DataProvider('unusableCodes')]
    public function test_a_code_that_became_unusable_restarts_without_contacting_the_bank(CodeStatus $status): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->setStatus(self::CODE, $status);

        $this->login()->assertRedirect('/')->assertSessionHasErrors(['code' => $status->message()]);

        $this->assertNull(session('registration'));
        $this->assertSame(['begin:'.$status->value], $this->store->attemptLog);
        Http::assertNothingSent();
    }

    public function test_every_attempt_answer_has_the_matching_message(): void
    {
        $this->assertSame(self::MSG_BUSY, LoginAttempt::Busy->message());
        $this->assertSame('', LoginAttempt::Reserved->message());
        foreach (self::unusableCodes() as [$status]) {
            $this->assertSame($status, LoginAttempt::from($status->value)->codeStatus());
            $this->assertSame($status->message(), LoginAttempt::from($status->value)->message());
        }
        $this->assertNull(LoginAttempt::Busy->codeStatus());
    }

    public function test_an_outage_when_reserving_never_contacts_the_bank(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->unavailable = true;

        $this->login()->assertRedirect('/login')
            ->assertSessionHasErrors(['login' => 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้งในอีกสักครู่']);

        Http::assertNothingSent();
    }

    public function test_a_release_that_fails_does_not_hold_up_the_customer(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->endAttemptUnavailable = true;

        $this->login()->assertRedirect('/approve');

        $this->assertContains('could not release a register-code login attempt; it will expire', $this->logLines);
        $this->assertSame(1, $this->store->inFlight[$this->codeHash], 'left to expire in the database');
    }

    public function test_a_failure_that_cannot_be_recorded_is_not_released_as_uncounted(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);
        $this->store->recordFailureUnavailable = true;

        $this->login()->assertRedirect('/login');

        $this->assertSame(['begin:ok', 'record:'.$this->store->lastReservationId], $this->store->attemptLog);
        $this->assertSame(1, $this->store->inFlight[$this->codeHash]);
    }

    /**
     * Interleaved requests: each one reserves before the bank sees it, so
     * reservations still held by slower requests count towards the limit.
     */
    public function test_reservations_held_by_parallel_requests_cap_the_credential_submissions(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);
        $this->store->inFlight[$this->codeHash] = 3;

        $statuses = [];
        for ($i = 1; $i <= 6; $i++) {
            $this->login("198.51.100.{$i}");
            $statuses[] = $this->sessionError('login') === self::MSG_BUSY ? 'busy' : 'sent';
        }

        $this->assertSame(['sent', 'sent', 'busy', 'busy', 'busy', 'busy'], $statuses);
        $this->assertSame(2, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count());
        $this->assertSame(2, $this->store->failedLogins[$this->codeHash]);
    }

    private function login(string $ip = '203.0.113.7'): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip])->from('/login')
            ->post('/login', ['username' => 'alice', 'password' => 'pw', 'webhook_url' => 'https://hooks.example.com/wrapbiz']);
    }

    private function sessionError(string $key): string
    {
        $errors = session('errors');

        return $errors instanceof ViewErrorBag
            ? (string) $errors->first($key)
            : (string) ($errors['default']['messages'][$key][0] ?? '');
    }
}
