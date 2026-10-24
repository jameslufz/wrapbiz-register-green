<?php

namespace Tests\Feature;

use App\Wrapbiz\AccountState;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\RegistrationRejected;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\RegistrationStoreUnavailable;
use App\Wrapbiz\RejectionReason;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ViewErrorBag;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeBank;
use Tests\Support\RecordingStore;
use Tests\TestCase;

final class RegistrationFlowTest extends TestCase
{
    private const string CODE = 'reg-code-0123456789abcdef';

    private const string PASSWORD = 'Sup3r-Secret-Pässword!';

    private const string WEBHOOK = 'https://hooks.example.com/wrapbiz';

    private const string MASKED_FIRST = 'xxx-x-x6789-x';

    private const string MASKED_SECOND = 'xxx-x-x5432-x';

    private RecordingStore $store;

    /** @var list<string> */
    private array $logLines = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new RecordingStore([self::CODE]);
        $this->app->instance(RegistrationStore::class, $this->store);
        Log::listen(function ($message) {
            $this->logLines[] = $message->message.' '.json_encode($message->context);
        });
    }

    public function test_happy_path_registers_selected_accounts_and_destroys_the_session(): void
    {
        FakeBank::fake();

        $this->get('/')->assertOk()->assertSee('รหัสลงทะเบียน');
        $this->post('/code', ['code' => self::CODE])->assertRedirect('/login');
        $this->assertPasswordNotInSession();

        $this->get('/login')->assertOk()->assertSee('view-only')->assertSee('เซสชัน K BIZ หมดอายุ');
        $this->login()->assertRedirect('/approve');
        $this->assertPasswordNotInSession();
        $this->assertNotEmpty(session('registration.bank_cookies'));

        $this->get('/approve')->assertOk()->assertSee('data:image/png;base64,', false);

        $this->postJson('/approve/status')->assertOk()->assertExactJson(['state' => 'approved', 'redirect' => route('registration.accounts')]);
        $this->assertNull(session('registration.bank_cookies'), 'bank cookie jar dropped after login');
        $this->assertPasswordNotInSession();

        $page = $this->get('/accounts')->assertOk()
            ->assertSee(self::MASKED_FIRST)
            ->assertSee(self::MASKED_SECOND)
            ->assertSee('name="list" value="'.session('registration.list_nonce').'"', false)
            ->assertDontSee('1234567890')
            ->assertDontSee('0987654321');
        $this->assertStringNotContainsString('value="0"', (string) $page->getContent(), 'positional indexes are no longer accepted');

        $response = $this->selectAccount(1);

        $response->assertOk()
            ->assertSee('ลงทะเบียนสำเร็จ')
            ->assertSee(self::MASKED_SECOND)
            ->assertSee(base64_encode(sodium_crypto_sign_publickey_from_secretkey($this->signingSecretKey)))
            ->assertSee('verifyWrapbizWebhook')
            ->assertSee('wrapbiz_handle_webhook')
            ->assertSee('data.transaction.ref')
            ->assertHeader('Cache-Control', 'no-store, private');

        $this->assertCount(1, $this->store->registrations);
        $registration = $this->store->registrations[0];
        $account = $registration->accounts[0];
        $response->assertSee($account->id);

        $this->assertSame(hash('sha256', self::CODE, true), $registration->codeHash);
        $this->assertSame('kbank', $registration->provider);
        $this->assertSame(self::WEBHOOK, $registration->webhookUrl);
        $this->assertSame(hash_hmac('sha256', 'kbank:org:ORG-9', str_repeat('f', 32), true), $registration->orgFingerprint);
        $this->assertSame(hash_hmac('sha256', '203.0.113.7', str_repeat('i', 32), true), $registration->ipHash);
        $this->assertSame(self::MASKED_SECOND, $account->masked);
        $this->assertSame(hash_hmac('sha256', 'kbank:0987654321', str_repeat('f', 32), true), $account->fingerprint);

        // Cross-repo contract: the worker's strict decoder accepts exactly these keys, once each, all strings.
        $this->assertSame(json_encode([
            'connection_id' => $registration->connectionId,
            'session_token' => 'session-token-xyz',
            'user_ref' => 'U-1',
            'org_id' => 'ORG-9',
            'customer_type' => 'C',
        ], JSON_UNESCAPED_SLASHES), sodium_crypto_box_seal_open($registration->sealedCredential, $this->sealSecretKeypair));
        $this->assertSame(
            json_encode(['account_id' => $account->id, 'account_no' => '0987654321', 'account_type' => 'CA']),
            sodium_crypto_box_seal_open($account->sealed, $this->sealSecretKeypair),
        );

        $this->assertNull(session('registration'), 'registration state destroyed');
        $this->get('/accounts')->assertRedirect('/');

        $this->assertNoSecretsLogged();
    }

    public function test_exactly_the_chosen_account_is_sent(): void
    {
        $this->reachAccountSelection();
        $this->selectAccount(1)->assertOk();

        $this->assertCount(1, $this->store->registrations[0]->accounts);
        $this->assertSame(self::fingerprintOf('0987654321'), $this->store->registrations[0]->accounts[0]->fingerprint);
    }

    public function test_a_reattached_account_shows_its_existing_id_next_to_its_number(): void
    {
        $this->store->reattachedIndexes = [0 => 'existing-account-id'];
        $this->reachAccountSelection();

        $response = $this->selectAccount(0)->assertOk();

        $sent = $this->store->registrations[0]->accounts[0];
        $this->assertSame(self::MASKED_FIRST, $sent->masked);
        $this->assertMatchesRegularExpression(
            '#<tr>\s*<td><code>'.preg_quote(self::MASKED_FIRST, '#').'</code></td>\s*<td>\s*<code class="break">existing-account-id</code>\s*<p class="hint">เชื่อมต่อบัญชีเดิมอีกครั้ง#u',
            (string) $response->getContent(),
        );
        $response->assertDontSee($sent->id);
    }

    public function test_a_reattached_account_with_a_gap_beyond_the_catch_up_window_shows_the_missed_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'gap-account'];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-09-30T10:15:00Z')];
        $this->reachAccountSelection();

        $html = (string) $this->selectAccount(0)->assertOk()->getContent();

        $this->assertSame(1, substr_count($html, 'มีช่วงที่ระบบส่งรายการให้ไม่ได้'));
        $this->assertStringContainsString('รายการตั้งแต่ 2026-09-30 17:15 ถึงสิ้นวันที่ 2026-10-07 (เวลาประเทศไทย)', $html);
        $this->assertMatchesRegularExpression('#gap-account</code>.*?มีช่วงที่ระบบส่งรายการให้ไม่ได้#su', $html);
        $this->assertStringContainsString('ย้อนหลังไม่เกิน 7 วัน', $html);
        $this->assertStringNotContainsString('31 วัน', $html);
    }

    public function test_a_reattached_account_within_the_window_shows_no_missed_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'recent'];
        $this->store->registeredAt = [0 => new \DateTimeImmutable('2026-01-01T00:00:00Z')];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-10-15T00:00:00+07:00')];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()->assertSee('recent')->assertDontSee('มีช่วงที่ระบบส่งรายการให้ไม่ได้');
    }

    public function test_a_never_polled_reattached_account_registered_within_the_window_shows_no_missed_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'never-polled'];
        $this->store->registeredAt = [0 => new \DateTimeImmutable('2026-10-09T00:00:00+07:00')];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()->assertSee('never-polled')->assertDontSee('มีช่วงที่ระบบส่งรายการให้ไม่ได้');
    }

    public function test_a_hand_over_shows_the_gap_with_seconds_the_delivered_count_and_the_fresh_endpoint(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'taken-over'];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-09-01T00:00:00Z')];
        $this->store->handovers = [0 => [new \DateTimeImmutable('2026-10-01T03:04:05Z'), new \DateTimeImmutable('2026-10-16T01:55:00Z'), 3, 2]];
        $this->reachAccountSelection();

        $html = (string) $this->selectAccount(0)->assertOk()->getContent();

        $this->assertStringContainsString('รายการระหว่าง 2026-10-01 10:04:05 ถึง 2026-10-16 08:55:00 (เวลาประเทศไทย)', $html);
        $this->assertStringContainsString('อาจไม่ได้ส่งเป็น webhook เพราะมีการเปลี่ยนผู้ใช้ KBiz กรุณาตรวจสอบช่วงนี้กับ statement ธนาคารเอง', $html);
        $this->assertStringContainsString('ในช่วงนี้ส่งสำเร็จแล้ว 3 รายการ — กรุณาอย่าบันทึกรายการเหล่านั้นซ้ำ', $html);
        $this->assertStringContainsString('ยังค้างส่งหรือส่งไม่สำเร็จอีก 2 รายการ — รายการเหล่านี้อาจไม่ถึงระบบของคุณ กรุณาติดต่อผู้ดูแล', $html);
        $this->assertStringNotContainsString('(ไปที่ Webhook URL เดิม)', $html);
        // SEC-R10-05: what happens to old queued events is the operator's call, not an offer to the new user.
        $this->assertStringContainsString('รายการเก่าที่ยังค้างส่งยังคงอยู่กับ Webhook URL ของผู้ใช้เดิม และผู้ดูแลเป็นผู้ตัดสินว่าจะจัดการรายการเหล่านั้นอย่างไร', $html);
        $this->assertStringNotContainsString('หากต้องการให้ส่งซ้ำ', $html);
        $this->assertStringNotContainsString('URL เดิม', $html);
        $this->assertStringContainsString('ใช้ webhook endpoint ใหม่ตาม Webhook URL ด้านล่าง', $html);
        $this->assertStringContainsString('รายการแรกที่ส่งถึงคุณคือลำดับถัดจากรายการสุดท้ายที่ส่งให้ผู้ใช้เดิม', $html);
        $this->assertStringNotContainsString('มีช่วงที่ระบบส่งรายการให้ไม่ได้', $html, 'no catch-up range: a hand-over starts fresh');
        $this->assertStringNotContainsString('เชื่อมต่อบัญชีเดิมอีกครั้งหลังเซสชัน K BIZ หมดอายุ', $html);
    }

    public function test_a_hand_over_without_deliveries_in_the_gap_says_so(): void
    {
        $this->store->reattachedIndexes = [0 => 'taken-over'];
        $this->store->handovers = [0 => [new \DateTimeImmutable('2026-10-01T03:04:05Z'), new \DateTimeImmutable('2026-10-16T01:55:00Z'), 0, 0]];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()
            ->assertSee('ยังไม่มีรายการในช่วงนี้ที่ส่งสำเร็จ')
            ->assertDontSee('กรุณาอย่าบันทึกรายการเหล่านั้นซ้ำ')
            ->assertDontSee('ยังค้างส่งหรือส่งไม่สำเร็จ', false);
    }

    /** BUG-R8-02: an empty-gap hand-over is still a hand-over. */
    public function test_an_empty_gap_hand_over_shows_the_new_endpoint_and_no_catch_up_text(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'taken-over'];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-09-01T00:00:00Z')];
        $this->store->handovers = [0 => [null, null, null]];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()
            ->assertSee('ใช้ webhook endpoint ใหม่ตาม Webhook URL ด้านล่าง')
            ->assertDontSee('อาจไม่ได้ส่ง')
            ->assertDontSee('มีช่วงที่ระบบส่งรายการให้ไม่ได้')
            ->assertDontSee('เชื่อมต่อบัญชีเดิมอีกครั้งหลังเซสชัน K BIZ หมดอายุ')
            ->assertDontSee('ย้อนหลังไม่เกิน');
    }

    public function test_a_same_user_re_login_shows_no_handover_text(): void
    {
        $this->store->reattachedIndexes = [0 => 'same-user'];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()
            ->assertSee('เชื่อมต่อบัญชีเดิมอีกครั้งหลังเซสชัน K BIZ หมดอายุ')
            ->assertDontSee('เพราะมีการเปลี่ยนผู้ใช้ KBiz')
            ->assertDontSee('webhook endpoint ใหม่');
    }

    /** BUG-R3-03: the worker polls a never-polled reattached account from its registration date. */
    public function test_a_never_polled_reattached_account_shows_the_range_since_it_was_registered(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'never-polled'];
        $this->store->registeredAt = [0 => new \DateTimeImmutable('2026-09-26T02:30:00Z')];
        $this->reachAccountSelection();

        $html = (string) $this->selectAccount(0)->assertOk()->getContent();

        $this->assertStringContainsString('รายการตั้งแต่ 2026-09-26 09:30 ถึงสิ้นวันที่ 2026-10-07 (เวลาประเทศไทย)', $html);
    }

    /** wrapbiz round 27 (FIN-2601): no audited catch-up limit, so no range, only the warning. */
    public function test_a_reattached_account_without_a_catch_up_window_shows_a_warning_instead_of_a_range(): void
    {
        $this->store->catchUpDays = null;
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'unknown-window'];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-09-30T10:15:00Z')];
        $this->reachAccountSelection();

        $html = (string) $this->selectAccount(0)->assertOk()->getContent();

        $this->assertSame(1, substr_count($html, 'ยังบอกไม่ได้ว่ามีช่วงที่ระบบส่งรายการให้ไม่ได้หรือไม่'));
        $this->assertStringContainsString('(ตั้งแต่ 2026-09-30 17:15 เวลาประเทศไทย)', $html);
        $this->assertMatchesRegularExpression('#unknown-window</code>.*?ยังบอกไม่ได้ว่ามีช่วงที่ระบบส่งรายการให้ไม่ได้หรือไม่#su', $html);
        $this->assertStringNotContainsString('มีช่วงที่ระบบส่งรายการให้ไม่ได้:', $html);
        $this->assertStringNotContainsString('ย้อนหลังไม่เกิน', $html);
    }

    public function test_a_never_polled_reattached_account_without_a_registration_time_shows_no_range(): void
    {
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'never-polled'];
        $this->reachAccountSelection();

        $this->selectAccount(0)->assertOk()->assertSee('never-polled')->assertDontSee('มีช่วงที่ระบบส่งรายการให้ไม่ได้');
    }

    public function test_the_catch_up_window_is_the_one_register_connection_returned(): void
    {
        $this->store->catchUpDays = 14;
        $this->travelTo(new \DateTimeImmutable('2026-10-16T09:00:00+07:00'));
        $this->store->reattachedIndexes = [0 => 'month-gap'];
        $this->store->watermarks = [0 => new \DateTimeImmutable('2026-09-10T10:00:00+07:00')];
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->get('/accounts')->assertOk()->assertDontSee('14 วัน')->assertSee('หน้าถัดไปจะแจ้งช่วงนั้น');

        $html = (string) $this->selectAccount(0)->assertOk()->getContent();

        $this->assertSame(1, substr_count($html, 'มีช่วงที่ระบบส่งรายการให้ไม่ได้'));
        $this->assertStringContainsString('รายการตั้งแต่ 2026-09-10 10:00 ถึงสิ้นวันที่ 2026-09-30 (เวลาประเทศไทย)', $html);
        $this->assertStringContainsString('ย้อนหลังไม่เกิน 14 วัน', $html);
        $this->assertStringNotContainsString('7 วัน', $html);
    }

    /**
     * @return iterable<string, array{CodeStatus, string}>
     */
    public static function unusableCodes(): iterable
    {
        yield 'unknown' => [CodeStatus::Unknown, 'รหัสลงทะเบียนไม่ถูกต้อง'];
        yield 'used' => [CodeStatus::Used, 'การลงทะเบียนอาจเสร็จสมบูรณ์ไปแล้ว'];
        yield 'expired' => [CodeStatus::Expired, 'หมดอายุแล้ว'];
        yield 'locked' => [CodeStatus::Locked, 'ถูกล็อก'];
    }

    #[DataProvider('unusableCodes')]
    public function test_code_status_is_explained_precisely(CodeStatus $status, string $message): void
    {
        $this->store->setStatus(self::CODE, $status);

        $this->from('/')->post('/code', ['code' => self::CODE])->assertRedirect('/');

        $this->assertStringContainsString($message, $this->sessionError('code'));
        $this->assertNull(session('registration'));
    }

    public function test_codes_from_the_code_create_cli_are_accepted(): void
    {
        $code = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->assertSame(43, strlen($code));
        $this->app->instance(RegistrationStore::class, new RecordingStore([$code]));

        $this->post('/code', ['code' => "  {$code}\n"])->assertRedirect('/login');
        $this->assertSame(bin2hex(hash('sha256', $code, true)), session('registration.code_hash'));
    }

    public function test_malformed_codes_are_rejected_without_a_database_call(): void
    {
        $this->store->unavailable = true;

        $this->from('/')->post('/code', ['code' => 'short'])->assertSessionHasErrors(['code' => CodeStatus::Unknown->message()]);
        $this->from('/')->post('/code', ['code' => ''])->assertSessionHasErrors(['code' => 'กรุณากรอกรหัสลงทะเบียน']);
        $this->from('/')->post('/code', ['code' => str_repeat('a', 257)])->assertSessionHasErrors('code');
        $this->from('/')->post('/code', ['code' => 'reg-code'."\u{200B}".'-0123456789abcdef'])->assertSessionHasErrors(['code' => CodeStatus::Unknown->message()]);

        $this->get('/login')->assertRedirect('/');
    }

    public function test_database_outage_on_code_check_shows_a_friendly_error(): void
    {
        $this->store->unavailable = true;

        $this->from('/')->post('/code', ['code' => self::CODE])
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้งในอีกสักครู่']);
    }

    public function test_code_attempts_are_rate_limited_per_ip(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->from('/')->post('/code', ['code' => 'wrong-code-0123456789'])->assertSessionHasErrors('code');
        }

        $this->from('/')->post('/code', ['code' => self::CODE])
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => 'ลองหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่']);
        $this->assertNull(session('registration'));

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->from('/')->post('/code', ['code' => self::CODE])
            ->assertRedirect('/login');
    }

    public function test_login_attempts_are_rate_limited_per_ip(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => Http::response('down', 503)]);
        $this->post('/code', ['code' => self::CODE]);

        for ($i = 0; $i < 5; $i++) {
            $this->from('/login')->post('/login', $this->loginForm())->assertSessionHasErrors('login');
        }
        $this->from('/login')->post('/login', $this->loginForm())
            ->assertSessionHasErrors(['login' => 'ลองหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่']);

        Http::assertSentCount(5);
        $this->assertSame([], $this->store->failedLogins, 'bank outages never count against the code');
        $this->assertPasswordNotInSession();
    }

    public function test_invalid_webhook_url_never_reaches_the_bank(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);

        foreach ([
            'http://hooks.example.com/x' => 'URL ต้องขึ้นต้นด้วย https://',
            'https://127.0.0.1/x' => 'IP ภายใน',
            'https://hooks.example.com:8443/x' => 'พอร์ต 443',
            'https://u:p@hooks.example.com/x' => 'ชื่อผู้ใช้หรือรหัสผ่าน',
            'https://hooks.example.com/%ZZ' => 'รูปแบบ URL ไม่ถูกต้อง',
        ] as $url => $message) {
            $response = $this->from('/login')->post('/login', [...$this->loginForm(), 'webhook_url' => $url]);
            $response->assertRedirect('/login')->assertSessionHasErrors('webhook_url');
            $this->assertStringContainsString($message, $this->sessionError('webhook_url'));
            $this->assertSame($url, session('_old_input.webhook_url'));
            $this->assertPasswordNotInSession();
        }

        Http::assertNothingSent();
    }

    public function test_missing_login_fields_show_thai_messages_and_password_is_not_flashed(): void
    {
        $this->post('/code', ['code' => self::CODE]);

        $this->from('/login')->post('/login', ['username' => 'alice', 'password' => self::PASSWORD])
            ->assertSessionHasErrors(['webhook_url' => 'กรุณากรอก Webhook URL']);

        $this->assertSame('alice', session('_old_input.username'));
        $this->assertNull(session('_old_input.password'));
        $this->assertPasswordNotInSession();
    }

    public function test_wrong_credentials_count_against_the_code_and_warn_about_the_lock(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);

        $this->from('/login')->post('/login', $this->loginForm())->assertRedirect('/login');

        $error = $this->sessionError('login');
        $this->assertStringContainsString('เข้าสู่ระบบ K BIZ ไม่สำเร็จ', $error);
        $this->assertStringContainsString('รหัสลงทะเบียนจะถูกล็อก', $error);
        $this->assertSame(1, $this->store->failedLogins[hash('sha256', self::CODE, true)]);
        $this->assertPasswordNotInSession();
        $this->assertNoSecretsLogged();
        $this->assertTrue(collect($this->logLines)->contains(fn ($l) => str_contains($l, 'login_failed')));
    }

    public function test_code_locks_after_five_wrong_credentials_and_the_bank_is_not_contacted_again(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);

        for ($i = 1; $i < RecordingStore::LOCK_AFTER; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])
                ->from('/login')->post('/login', $this->loginForm())->assertRedirect('/login');
        }
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.99'])
            ->from('/login')->post('/login', $this->loginForm())
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => CodeStatus::Locked->message()]);

        $this->assertSame(CodeStatus::Locked, $this->store->statusOf(self::CODE));
        $this->assertNull(session('registration'));
        $this->assertSame(RecordingStore::LOCK_AFTER, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count());
    }

    public function test_a_code_locked_elsewhere_stops_the_login_before_the_bank_is_contacted(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->setStatus(self::CODE, CodeStatus::Locked);

        $this->from('/login')->post('/login', $this->loginForm())
            ->assertRedirect('/')
            ->assertSessionHasErrors(['code' => CodeStatus::Locked->message()]);

        Http::assertNothingSent();
    }

    /**
     * @return iterable<string, array{\Closure(): mixed, string}>
     */
    public static function answersToTheCredentialSubmit(): iterable
    {
        yield 'page without a QR' => [fn () => Http::response('<p>bad password</p>'), 'เข้าสู่ระบบ K BIZ ไม่สำเร็จ'];
        yield '302' => [fn () => Http::response('', 302, ['Location' => 'https://bank.test/elsewhere']), 'ธนาคารตอบกลับในรูปแบบที่ระบบไม่รู้จัก'];
        yield '403' => [fn () => Http::response('no', 403), 'ไม่สามารถเชื่อมต่อธนาคารได้'];
        yield '503' => [fn () => Http::response('down', 503), 'ไม่สามารถเชื่อมต่อธนาคารได้'];
        yield 'oversized' => [fn () => Http::response(str_repeat('A', 3 * 1024 * 1024)), 'ธนาคารตอบกลับในรูปแบบที่ระบบไม่รู้จัก'];
    }

    #[DataProvider('answersToTheCredentialSubmit')]
    public function test_every_bank_answer_to_the_credentials_except_a_qr_counts_against_the_code(\Closure $response, string $message): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => $response()]);
        $this->post('/code', ['code' => self::CODE]);

        $this->from('/login')->post('/login', $this->loginForm())->assertRedirect('/login');

        $error = $this->sessionError('login');
        $this->assertStringContainsString($message, $error);
        $this->assertStringContainsString('รหัสลงทะเบียนจะถูกล็อก', $error);
        $this->assertSame([hash('sha256', self::CODE, true) => 1], $this->store->failedLogins);
    }

    public function test_five_bank_errors_on_the_credential_submit_lock_the_code(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('down', 503)]);
        $this->post('/code', ['code' => self::CODE]);

        for ($i = 1; $i <= RecordingStore::LOCK_AFTER; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])->from('/login')->post('/login', $this->loginForm());
        }

        $this->assertSame(CodeStatus::Locked, $this->store->statusOf(self::CODE));
        $this->assertSame(CodeStatus::Locked->message(), $this->sessionError('code'));
    }

    public function test_failures_before_the_bank_answered_the_credentials_do_not_count(): void
    {
        $this->post('/code', ['code' => self::CODE]);
        $unreachable = fn (Request $request) => Create::rejectionFor(new ConnectException('cURL error 7', new PsrRequest('POST', $request->url())));

        foreach ([
            'login page down' => [FakeBank::BASE_URL.'/p/one' => Http::response('down', 503)],
            'login page without token' => [FakeBank::BASE_URL.'/p/one' => Http::response('<html></html>')],
            'submit never connected' => [FakeBank::BASE_URL.'/p/two/submit' => $unreachable],
            'credentials accepted, QR image unusable' => [FakeBank::BASE_URL.'/p/two/submit' => Http::response(FakeBank::qrPage('javascript:alert(1)'))],
        ] as $case => $fake) {
            FakeBank::fake($fake);
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.random_int(1, 250)])
                ->from('/login')->post('/login', $this->loginForm())->assertRedirect('/login');
            $this->assertStringNotContainsString('รหัสลงทะเบียนจะถูกล็อก', $this->sessionError('login'), $case);
            $this->assertSame([], $this->store->failedLogins, $case);
        }
    }

    public function test_a_failure_that_cannot_be_recorded_does_not_continue_silently(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);
        $this->store->recordFailureUnavailable = true;

        $this->from('/login')->post('/login', $this->loginForm())
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['login' => 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้งในอีกสักครู่']);
    }

    public function test_database_outage_before_login_never_contacts_the_bank(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->store->unavailable = true;

        $this->from('/login')->post('/login', $this->loginForm())
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['login' => 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้งในอีกสักครู่']);

        Http::assertNothingSent();
    }

    public function test_global_bank_login_budget_caps_all_clients_together(): void
    {
        config(['wrapbiz.bank_logins_per_minute' => '2']);
        FakeBank::fake([FakeBank::BASE_URL.'/p/one' => Http::response('down', 503)]);
        $this->post('/code', ['code' => self::CODE]);

        foreach (['198.51.100.1', '198.51.100.2'] as $ip) {
            $this->withServerVariables(['REMOTE_ADDR' => $ip])->from('/login')->post('/login', $this->loginForm())
                ->assertSessionHasErrors(['login' => 'ไม่สามารถเชื่อมต่อธนาคารได้ในขณะนี้ กรุณาลองใหม่อีกครั้ง']);
        }
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.3'])->from('/login')->post('/login', $this->loginForm())
            ->assertSessionHasErrors(['login' => 'มีผู้ใช้งานเข้าสู่ระบบธนาคารพร้อมกันจำนวนมาก กรุณารอสักครู่แล้วลองใหม่']);

        $this->assertSame(2, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/one'))->count());
    }

    public function test_requests_that_never_reach_the_bank_do_not_use_the_global_budget(): void
    {
        config(['wrapbiz.bank_logins_per_minute' => '1']);
        FakeBank::fake();

        for ($i = 1; $i <= 4; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])->post('/login', $this->loginForm())->assertRedirect('/');
        }
        $this->post('/code', ['code' => self::CODE]);
        $this->from('/login')->post('/login', [...$this->loginForm(), 'webhook_url' => 'http://x.example.com/'])->assertSessionHasErrors('webhook_url');

        $this->login()->assertRedirect('/approve');
    }

    public function test_login_requires_an_accepted_code(): void
    {
        FakeBank::fake();

        $this->post('/login', $this->loginForm())->assertRedirect('/')->assertSessionHasErrors('code');
        Http::assertNothingSent();
    }

    public function test_pending_then_rejected_approval_returns_to_login_and_counts(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();

        Http::swap(new Factory(app('events')));
        Http::preventStrayRequests();
        Http::fakeSequence(FakeBank::BASE_URL.'/p/three')
            ->push(['k_wrap' => ['k_state' => 'WAIT']])
            ->push(['k_wrap' => ['k_state' => 'NO']]);

        $this->postJson('/approve/status')->assertExactJson(['state' => 'pending']);
        $this->postJson('/approve/status')->assertOk()->assertJson(['state' => 'rejected', 'redirect' => route('registration.login')]);

        $this->assertSame(1, $this->store->failedLogins[hash('sha256', self::CODE, true)]);
        $this->assertNull(session('registration.bank_cookies'));
        $this->assertNotNull(session('registration.code_hash'), 'code kept so the user can retry');
        $this->get('/login')->assertOk()->assertSee('การเข้าสู่ระบบถูกปฏิเสธ');
        $this->get('/approve')->assertRedirect('/login');
    }

    public function test_the_rejection_that_locks_the_code_sends_the_browser_to_the_start(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/three' => Http::response(['k_wrap' => ['k_state' => 'NO']])]);
        $this->post('/code', ['code' => self::CODE]);
        $this->store->failedLogins[hash('sha256', self::CODE, true)] = RecordingStore::LOCK_AFTER - 1;
        $this->login();

        $this->postJson('/approve/status')->assertExactJson([
            'state' => 'locked',
            'redirect' => route('registration.code'),
            'message' => CodeStatus::Locked->message(),
        ]);

        $this->assertNull(session('registration'));
        $this->get('/')->assertSee('ถูกล็อก');
    }

    public function test_expired_qr_returns_to_login_without_calling_the_bank(): void
    {
        Date::setTestNow('2026-10-16 10:00:00');
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();

        Date::setTestNow('2026-10-16 10:05:00');
        $this->postJson('/approve/status')->assertJson(['state' => 'expired', 'redirect' => route('registration.login')]);

        Http::assertNotSent(fn (Request $r) => FakeBank::sentTo($r, '/p/three'));
        $this->assertSame([], $this->store->failedLogins);
    }

    public function test_bank_failure_after_approval_returns_to_login(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/five' => Http::response('<p>nothing</p>')]);
        $this->post('/code', ['code' => self::CODE]);
        $this->login();

        $this->postJson('/approve/status')->assertJson(['state' => 'failed', 'redirect' => route('registration.login')]);
        $this->assertNull(session('registration.bank_session'));
        $this->assertNoSecretsLogged();
    }

    public function test_polling_out_of_order_asks_the_browser_to_restart(): void
    {
        $this->postJson('/approve/status')->assertJson(['state' => 'restart', 'redirect' => route('registration.code')]);
    }

    public function test_no_javascript_status_check_redirects(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();

        $this->post('/approve/status')->assertRedirect('/accounts');
    }

    public function test_account_selection_is_validated_against_the_listed_accounts(): void
    {
        $this->reachAccountSelection();
        $nonce = session('registration.list_nonce');

        $choose = 'กรุณาเลือก 1 บัญชีที่ต้องการลงทะเบียน';
        $invalid = 'รายการบัญชีที่เลือกไม่ถูกต้อง กรุณาเลือกใหม่';
        $this->from('/accounts')->post('/accounts', ['list' => $nonce])->assertSessionHasErrors(['account' => $choose]);
        $this->from('/accounts')->post('/accounts', ['list' => $nonce, 'accounts' => [$this->tokenFor(0)]])
            ->assertSessionHasErrors(['account' => $choose]);
        $this->from('/accounts')->post('/accounts', ['list' => $nonce, 'account' => '0'])->assertSessionHasErrors(['account' => $invalid]);
        $this->from('/accounts')->post('/accounts', ['list' => $nonce, 'account' => str_repeat('a', 32)])->assertSessionHasErrors(['account' => $invalid]);
        $this->from('/accounts')->post('/accounts', ['list' => $nonce, 'account' => [$this->tokenFor(0)]])->assertSessionHasErrors(['account' => $invalid]);
        $this->from('/accounts')->post('/accounts', ['list' => $nonce, 'account' => [$this->tokenFor(0), $this->tokenFor(1)]])->assertSessionHasErrors(['account' => $invalid]);

        $this->assertSame([], $this->store->registrations);
        $this->assertNotNull(session('registration.bank_session'));
    }

    public function test_a_form_without_the_current_list_nonce_is_refused(): void
    {
        $this->reachAccountSelection();

        foreach ([null, '', 'stale-nonce', ['array']] as $list) {
            $this->post('/accounts', ['list' => $list, 'account' => $this->tokenFor(0)])
                ->assertRedirect('/accounts')
                ->assertSessionHasErrors(['account' => 'รายการบัญชีมีการเปลี่ยนแปลง (อาจมีการเข้าสู่ระบบใหม่จากแท็บอื่น) กรุณาตรวจสอบและเลือกบัญชีใหม่จากรายการด้านล่าง']);
        }

        $this->assertSame([], $this->store->registrations);
    }

    public function test_bug_002_a_stale_tab_cannot_register_from_a_newer_account_list(): void
    {
        $this->reachAccountSelection();
        $tabA = ['list' => session('registration.list_nonce'), 'account' => $this->tokenFor(0)];

        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => [
            ['k_no' => '9999999999', 'k_kind' => 'SA'],
            ['k_no' => '1234567890', 'k_kind' => 'SA'],
        ]]])]);
        $this->post('/login', [...$this->loginForm(), 'username' => 'other-user'])->assertRedirect('/approve');
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);

        $this->post('/accounts', $tabA)->assertRedirect('/accounts');
        $this->assertSame([], $this->store->registrations);

        $this->get('/accounts')->assertSee('xxx-x-x9999-x')->assertSee('รายการบัญชีมีการเปลี่ยนแปลง');
    }

    public function test_sec_006b_posting_login_while_choosing_accounts_forgets_the_previous_bank_session(): void
    {
        $this->reachAccountSelection();
        $this->assertNotNull(session('registration.bank_session'));

        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->from('/login')->post('/login', $this->loginForm())->assertRedirect('/login');

        $this->assertSame('code_accepted', session('registration.stage'));
        $this->assertNull(session('registration.bank_session'));
        $this->assertNull(session('registration.accounts'));
        $this->assertNull(session('registration.list_nonce'));
        $this->get('/accounts')->assertRedirect('/login');
    }

    public function test_code_consumed_by_another_registration_says_it_may_have_completed(): void
    {
        $this->reachAccountSelection();
        $this->store->setStatus(self::CODE, CodeStatus::Used);

        $this->selectAccount(0)->assertRedirect('/')->assertSessionHasErrors('code');

        $message = $this->sessionError('code');
        $this->assertStringContainsString('การลงทะเบียนอาจเสร็จสมบูรณ์ไปแล้ว', $message);
        $this->assertStringNotContainsString('ไม่มีการบันทึก', $message);
        $this->assertNull(session('registration'));
    }

    public function test_code_that_expired_during_the_flow_says_nothing_was_saved(): void
    {
        $this->reachAccountSelection();
        $this->store->setStatus(self::CODE, CodeStatus::Expired);

        $this->selectAccount(0)->assertRedirect('/')->assertSessionHasErrors(['code' => CodeStatus::Expired->message()]);
    }

    public function test_bug_003_a_lost_response_after_commit_never_claims_nothing_was_saved(): void
    {
        $this->reachAccountSelection();
        $this->store->failAfterCommitWith = new RegistrationStoreUnavailable('08006');

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/')->assertSessionHasErrors('code');

        $message = $this->sessionError('code');
        $this->assertStringContainsString('ถูกใช้แล้ว', $message);
        $this->assertStringContainsString('ติดต่อผู้ดูแลระบบ', $message);
        $this->assertStringNotContainsString('ไม่มีการบันทึก', $message);
        $this->assertCount(1, $this->store->registrations);
    }

    public function test_bug_003_a_failure_before_commit_lets_the_customer_retry(): void
    {
        $this->reachAccountSelection();
        $this->store->failRegisterWith = new RegistrationStoreUnavailable('08006');

        $this->from('/accounts')->selectAccount(0)
            ->assertRedirect('/accounts')
            ->assertSessionHasErrors(['account' => 'ระบบขัดข้องชั่วคราว การลงทะเบียนยังไม่สำเร็จ กรุณากดลงทะเบียนอีกครั้ง']);
        $this->assertNotNull(session('registration.bank_session'));

        $this->store->failRegisterWith = null;
        $this->selectAccount(0)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_bug_003_unknown_outcome_when_the_status_check_also_fails(): void
    {
        $this->reachAccountSelection();
        $this->store->unavailable = true;

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $message = $this->sessionError('account');
        $this->assertStringContainsString('ไม่สามารถยืนยันได้ว่าการลงทะเบียนสำเร็จหรือไม่', $message);
        $this->assertStringNotContainsString('ไม่มีการบันทึก', $message);
    }

    public function test_back_button_after_success_cannot_register_again(): void
    {
        $this->reachAccountSelection();
        $form = ['list' => session('registration.list_nonce'), 'account' => $this->tokenFor(0)];
        $this->post('/accounts', $form)->assertOk();

        $this->post('/accounts', $form)->assertRedirect('/');
        $this->assertCount(1, $this->store->registrations);
    }

    public function test_already_registered_account_is_refused_with_the_agreed_message(): void
    {
        $this->reachAccountSelection();
        $this->store->failRegisterWith = new RegistrationRejected(RejectionReason::AccountAlreadyRegistered);

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertStringStartsWith('บัญชีนี้ลงทะเบียนแล้ว ติดต่อผู้ดูแล', $this->sessionError('account'));
        $this->assertNotNull(session('registration.bank_session'), 'the customer can deselect it and continue');
    }

    public function test_endpoint_conflict_and_invalid_accounts_keep_the_selection_page(): void
    {
        $this->reachAccountSelection();

        foreach ([
            [RejectionReason::EndpointConflict, 'Webhook URL คนละชุด'],
            [RejectionReason::EndpointUrlLocked, 'เปลี่ยน URL ไม่ได้ เพราะยังมีบัญชีอื่นใช้ endpoint นี้อยู่ ติดต่อผู้ดูแล'],
            [RejectionReason::EndpointDisabled, 'endpoint นี้ถูกปิดโดยผู้ดูแล ติดต่อผู้ดูแล'],
            [RejectionReason::InvalidAccounts, 'รายการบัญชีที่เลือกไม่ถูกต้อง'],
            [RejectionReason::InvalidInput, 'ไม่ผ่านการตรวจสอบของระบบ ยังไม่มีการบันทึกข้อมูลใด ๆ'],
        ] as [$reason, $message]) {
            $this->store->failRegisterWith = new RegistrationRejected($reason);
            $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');
            $this->assertStringContainsString($message, $this->sessionError('account'));
            $this->assertNotNull(session('registration.bank_session'), "{$reason->value}: nothing was saved, the selection stays");
            $this->assertSame(CodeStatus::Usable, $this->store->statusOf(self::CODE));
        }
    }

    public function test_restart_clears_everything(): void
    {
        $this->reachAccountSelection();

        $this->post('/restart')->assertRedirect('/');
        $this->assertNull(session('registration'));
    }

    public function test_pages_send_security_headers(): void
    {
        $response = $this->get('/');

        $response->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('Referrer-Policy', 'no-referrer');
        $csp = (string) $response->headers->get('Content-Security-Policy');
        $this->assertStringContainsString("frame-ancestors 'none'", $csp);
        $this->assertMatchesRegularExpression("/script-src 'nonce-[A-Za-z0-9+\\/=]+'/", $csp);
        preg_match("/'nonce-([^']+)'/", $csp, $m);
        $response->assertSee('nonce="'.$m[1].'"', false);
    }

    public function test_well_known_keys(): void
    {
        $public = sodium_crypto_sign_publickey_from_secretkey($this->signingSecretKey);

        $this->get('/.well-known/wrapbiz-keys.json')
            ->assertOk()
            ->assertHeader('Cache-Control', 'max-age=300, public')
            ->assertJson([
                'scheme' => 'standard-webhooks-v1a-ed25519',
                'keys' => [[
                    'kid' => 'k1', 'kty' => 'OKP', 'crv' => 'Ed25519',
                    'x' => rtrim(strtr(base64_encode($public), '+/', '-_'), '='),
                    'public_key_base64' => base64_encode($public),
                ]],
            ]);
    }

    private static function fingerprintOf(string $digits): string
    {
        return hash_hmac('sha256', 'kbank:'.$digits, str_repeat('f', 32), true);
    }

    /**
     * @return iterable<string, array{AccountState, string}>
     */
    public static function nonSelectableStates(): iterable
    {
        yield 'held (paused or fingerprint mismatch)' => [AccountState::Held, 'บัญชีนี้ถูกระงับ ติดต่อผู้ดูแล'];
        yield 'registered elsewhere' => [AccountState::Registered, 'บัญชีนี้ลงทะเบียนแล้ว ติดต่อผู้ดูแล'];
        yield 'this K BIZ user already has another account' => [AccountState::UserBound, 'ผู้ใช้ KBiz นี้ลงทะเบียนบัญชีอื่นไว้แล้ว — ถ้าต้องการเพิ่มบัญชี กรุณาสร้างผู้ใช้ KBiz ใหม่'];
    }

    #[DataProvider('nonSelectableStates')]
    public function test_a_non_selectable_account_is_shown_disabled_with_its_note_and_refused_if_posted(AccountState $state, string $note): void
    {
        $this->store->accountStates = [self::fingerprintOf('1234567890') => $state];
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);

        $html = (string) $this->get('/accounts')->assertOk()->getContent();

        $this->assertMatchesRegularExpression('/<input type="radio" name="account"[^>]*id="account-0"[^>]*aria-describedby="account-0-note"[^>]*disabled/s', $html);
        $this->assertStringContainsString('<p class="hint" id="account-0-note">'.$note.'</p>', $html);
        $this->assertDoesNotMatchRegularExpression('/<input type="radio"[^>]*id="account-1"[^>]*disabled/s', $html);
        $this->assertStringContainsString('id="accounts-submit"', $html);

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertSame($note, $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations, 'never sent to register_connection');
        $this->assertNotNull(session('registration.bank_session'), 'the customer can still register the other account');

        $this->selectAccount(1)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
        $this->assertCount(1, $this->store->registrations[0]->accounts);
    }

    public function test_a_reattachable_account_is_selectable_and_explains_the_re_login(): void
    {
        $this->store->accountStates = [self::fingerprintOf('0987654321') => AccountState::Reattachable];
        $this->reachAccountSelection();

        $html = (string) $this->get('/accounts')->assertOk()->getContent();

        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-1"[^>]*aria-describedby="account-1-note"/s', $html);
        $this->assertDoesNotMatchRegularExpression('/<input type="radio"[^>]*id="account-1"[^>]*disabled/s', $html);
        $this->assertStringContainsString('จะเชื่อมต่อบัญชีเดิมอีกครั้งด้วย account id เดิม', $html);
        $this->assertStringNotContainsString('aria-describedby="account-0-note"', $html, 'a new account needs no note');

        $this->store->reattachedIndexes = [0 => 'existing-id'];
        $this->selectAccount(1)->assertOk()->assertSee('existing-id');
    }

    public function test_states_are_asked_for_this_bank_user_and_every_listed_account(): void
    {
        $this->reachAccountSelection();

        $call = $this->store->accountStateCalls[0];
        $this->assertSame(hash_hmac('sha256', 'kbank:org:ORG-9', str_repeat('f', 32), true), $call['org']);
        $this->assertSame(hash_hmac('sha256', 'kbank:user:U-1', str_repeat('f', 32), true), $call['user']);
        $this->assertEqualsCanonicalizing([self::fingerprintOf('1234567890'), self::fingerprintOf('0987654321')], $call['fingerprints']);
        $this->assertNoSecretsLogged();
    }

    public function test_when_states_cannot_be_read_nothing_is_selectable_until_a_reload_succeeds(): void
    {
        $this->store->accountStatesUnavailable = true;
        $this->reachAccountSelection();

        $html = (string) $this->get('/accounts')->assertOk()->getContent();
        $this->assertStringContainsString('ระบบตรวจสอบสถานะบัญชีไม่ได้ชั่วคราว', $html);
        $this->assertStringContainsString('href="'.route('registration.accounts').'"', $html);
        $this->assertSame(2, preg_match_all('/<input type="radio"[^>]*disabled/s', $html));
        $this->assertStringNotContainsString('id="accounts-submit"', $html);

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');
        $this->assertStringContainsString('ยังตรวจสอบสถานะบัญชีที่เลือกไม่ได้', $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations, 'fails closed');

        $this->store->accountStatesUnavailable = false;
        $this->get('/accounts')->assertOk()->assertSee('id="accounts-submit"', false);
        $this->selectAccount(0)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_a_reload_reuses_the_states_of_this_list_without_spending_budget(): void
    {
        $this->reachAccountSelection();
        $this->store->accountStatesUnavailable = true;

        for ($i = 0; $i < 3; $i++) {
            $this->get('/accounts')->assertOk()->assertSee('id="accounts-submit"', false)->assertDontSee('ระบบตรวจสอบสถานะบัญชีไม่ได้ชั่วคราว');
        }

        $this->assertCount(1, $this->store->accountStateCalls);
        $this->assertSame(1, $this->store->statesCalls[hash('sha256', self::CODE, true)]);
        $this->selectAccount(0)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_states_remembered_for_an_earlier_list_are_never_used_for_a_new_one(): void
    {
        $this->reachAccountSelection();
        $stale = session('registration.account_states');

        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        session()->put('registration.account_states', $stale);
        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertStringContainsString('ยังตรวจสอบสถานะบัญชีที่เลือกไม่ได้', $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations);
        $this->get('/accounts')->assertOk();
        $this->assertCount(2, $this->store->accountStateCalls, 'the new list is asked about');
    }

    public function test_an_account_registered_meanwhile_makes_the_next_view_ask_again(): void
    {
        $this->reachAccountSelection();
        $this->store->failRegisterWith = new RegistrationRejected(RejectionReason::AccountAlreadyRegistered);
        $this->store->accountStates = [self::fingerprintOf('1234567890') => AccountState::Registered];

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertStringContainsString('บัญชีนี้ลงทะเบียนแล้ว', $this->sessionError('account'));
        $this->assertNull(session('registration.account_states'));
        $html = (string) $this->get('/accounts')->assertOk()->getContent();
        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-0"[^>]*disabled/s', $html);
        $this->assertCount(2, $this->store->accountStateCalls);
    }

    private const string MSG_EXHAUSTED = 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่';

    public function test_an_exhausted_code_is_refused_at_the_code_form_before_any_bank_call(): void
    {
        $this->store->spendStatesBudget(self::CODE);
        $bank = FakeBank::fake();

        $this->from('/')->post('/code', ['code' => self::CODE])->assertRedirect('/');

        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertNull(session('registration'));
        $this->assertCount(0, $bank->recorded());
    }

    public function test_a_code_exhausted_after_it_was_accepted_is_refused_at_login_before_any_bank_call(): void
    {
        $bank = FakeBank::fake();
        $this->post('/code', ['code' => self::CODE])->assertRedirect('/login');
        $this->store->spendStatesBudget(self::CODE);

        $this->login()->assertRedirect('/');

        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertCount(0, $bank->recorded());
        $this->assertSame(['begin:exhausted'], $this->store->attemptLog);
        $this->assertNoSecretsLogged();
    }

    public function test_a_budget_spent_by_another_tab_restarts_the_account_list(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->store->spendStatesBudget(self::CODE);

        $this->get('/accounts')->assertRedirect('/');

        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertNull(session('registration'));
        $this->assertNoSecretsLogged();
    }

    /** BUG-R6-01: a refused states call leaves the code exhausted, so it never reaches the bank again. */
    public function test_a_states_call_beyond_the_budget_exhausts_the_code_for_good(): void
    {
        $bank = FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $codeHash = hash('sha256', self::CODE, true);
        $this->store->statesFingerprints[$codeHash] = array_fill_keys(array_map(fn (int $i) => hash('sha256', "seen-{$i}", true), range(1, 49)), true);

        $this->get('/accounts')->assertRedirect('/');

        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertNull(session('registration'));
        $this->assertSame([], $this->store->registrations);
        $bankRequests = count($bank->recorded());

        $this->from('/')->post('/code', ['code' => self::CODE])->assertRedirect('/');
        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertNull(session('registration'));
        $this->assertCount($bankRequests, $bank->recorded(), 'no bank request after the refusal');
    }

    public function test_a_lost_response_on_an_exhausted_code_keeps_the_list_so_the_customer_can_retry(): void
    {
        $codeHash = hash('sha256', self::CODE, true);
        $this->store->statesCalls[$codeHash] = RecordingStore::STATES_CALLS - 1;
        $this->reachAccountSelection();
        $this->store->failRegisterWith = new RegistrationStoreUnavailable('08006');

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertSame('ระบบขัดข้องชั่วคราว การลงทะเบียนยังไม่สำเร็จ กรุณากดลงทะเบียนอีกครั้ง', $this->sessionError('account'));
        $this->assertNotNull(session('registration.bank_session'));
        $this->store->failRegisterWith = null;
        $this->selectAccount(0)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_the_tenth_states_call_still_lets_the_customer_register(): void
    {
        $codeHash = hash('sha256', self::CODE, true);
        $this->store->statesCalls[$codeHash] = RecordingStore::STATES_CALLS - 1;
        $this->reachAccountSelection();
        $this->assertSame(CodeStatus::Exhausted, $this->store->codeStatus($codeHash), 'no new bank login with this code');

        $this->selectAccount(0)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    private const string MSG_USER_BOUND = 'ผู้ใช้ KBiz นี้ลงทะเบียนบัญชีอื่นไว้แล้ว — ถ้าต้องการเพิ่มบัญชี กรุณาสร้างผู้ใช้ KBiz ใหม่';

    /** The binding key of the K BIZ user FakeBank logs in as: organisation and user fingerprint. */
    private static function boundUser(): string
    {
        return hash_hmac('sha256', 'kbank:org:ORG-9', str_repeat('f', 32), true).hash_hmac('sha256', 'kbank:user:U-1', str_repeat('f', 32), true);
    }

    public function test_a_user_bound_to_one_account_can_only_reattach_that_account(): void
    {
        $this->store->userBindings[self::boundUser()] = self::fingerprintOf('0987654321');
        $this->store->accountStates = [self::fingerprintOf('0987654321') => AccountState::Reattachable];
        $this->reachAccountSelection();

        $html = (string) $this->get('/accounts')->assertOk()->getContent();

        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-0"[^>]*aria-describedby="account-0-note"[^>]*disabled/s', $html);
        $this->assertStringContainsString('<p class="hint" id="account-0-note">'.self::MSG_USER_BOUND.'</p>', $html);
        $this->assertDoesNotMatchRegularExpression('/<input type="radio"[^>]*id="account-1"[^>]*disabled/s', $html);
        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');
        $this->assertSame(self::MSG_USER_BOUND, $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations);

        $this->store->reattachedIndexes = [0 => 'kept-id'];
        $this->selectAccount(1)->assertOk()->assertSee('kept-id');
    }

    public function test_a_user_bound_meanwhile_is_refused_and_the_list_is_asked_again(): void
    {
        $this->reachAccountSelection();
        $this->store->userBindings[self::boundUser()] = self::fingerprintOf('5555555555');

        $this->from('/accounts')->selectAccount(0)->assertRedirect('/accounts');

        $this->assertSame(self::MSG_USER_BOUND, $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations);
        $this->assertNull(session('registration.account_states'));
        $this->get('/accounts')->assertOk()
            ->assertSee('ไม่มีบัญชีในรายการนี้ที่ลงทะเบียนได้')
            ->assertDontSee('id="accounts-submit"', false);
        $this->assertCount(2, $this->store->accountStateCalls);
    }

    public function test_the_account_page_is_a_single_choice_that_keeps_the_choice_after_an_error(): void
    {
        $this->reachAccountSelection();
        $html = (string) $this->get('/accounts')->assertOk()->getContent();
        $this->assertSame(2, preg_match_all('/<input type="radio" name="account"/', $html));
        $this->assertStringNotContainsString('type="checkbox"', $html);
        $this->assertStringNotContainsString('checked', $html, 'nothing is preselected');

        $this->store->failRegisterWith = new RegistrationRejected(RejectionReason::EndpointUrlLocked);
        $this->from('/accounts')->selectAccount(1)->assertRedirect('/accounts');

        $html = (string) $this->get('/accounts')->assertOk()->getContent();
        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-1"[^>]*checked/s', $html);
        $this->assertDoesNotMatchRegularExpression('/<input type="radio"[^>]*id="account-0"[^>]*checked/s', $html);
    }

    public function test_the_one_account_rule_is_explained_before_login_and_after_success(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->get('/login')->assertSee('ผู้ใช้ K BIZ หนึ่งคนลงทะเบียนได้หนึ่งบัญชีเท่านั้น');
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->get('/accounts')->assertSee('เลือกได้ 1 บัญชี');

        $this->selectAccount(0)->assertOk()
            ->assertSee('ผู้ใช้ K BIZ นี้ผูกกับบัญชีนี้แล้วและใช้ลงทะเบียนบัญชีอื่นไม่ได้')
            ->assertSee('ลงทะเบียนบัญชีอื่น (ใช้ผู้ใช้ K BIZ ใหม่)');
    }

    public function test_an_exhausted_states_budget_reported_by_register_also_restarts(): void
    {
        $this->reachAccountSelection();
        $this->store->failRegisterWith = new RegistrationRejected(RejectionReason::StatesBudgetExhausted);

        $this->selectAccount(0)->assertRedirect('/');

        $this->assertSame(self::MSG_EXHAUSTED, $this->sessionError('code'));
        $this->assertNull(session('registration'));
    }

    public function test_a_list_longer_than_the_budget_asks_about_the_first_fifty_accounts_only(): void
    {
        $numbers = array_map(fn (int $i) => sprintf('10000000%02d', $i), range(0, 51));
        FakeBank::fake([FakeBank::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => array_map(
            fn (string $number) => ['k_no' => $number, 'k_kind' => 'SA'],
            $numbers,
        )]])]);
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);

        $html = (string) $this->get('/accounts')->assertOk()->getContent();

        $this->assertCount(1, $this->store->accountStateCalls);
        $this->assertSame(array_map(self::fingerprintOf(...), array_slice($numbers, 0, 50)), $this->store->accountStateCalls[0]['fingerprints']);
        $note = 'รหัสลงทะเบียนหนึ่งรหัสตรวจสอบได้สูงสุด 50 บัญชี บัญชีนี้จึงเลือกไม่ได้ ติดต่อผู้ดูแล';
        $this->assertDoesNotMatchRegularExpression('/<input type="radio"[^>]*id="account-49"[^>]*disabled/s', $html);
        $this->assertMatchesRegularExpression('/<input type="radio"[^>]*id="account-50"[^>]*aria-describedby="account-50-note"[^>]*disabled/s', $html);
        $this->assertStringContainsString('<p class="hint" id="account-51-note">'.$note.'</p>', $html);
        $this->assertStringNotContainsString('id="account-0-note"', $html);

        $this->from('/accounts')->selectAccount(50)->assertRedirect('/accounts');
        $this->assertSame($note, $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations);
        $this->selectAccount(49)->assertOk()->assertSee('ลงทะเบียนสำเร็จ');
    }

    public function test_a_code_that_stopped_being_usable_restarts_from_the_account_list(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->store->setStatus(self::CODE, CodeStatus::Expired);

        $this->get('/accounts')->assertRedirect('/');

        $this->assertStringContainsString('หมดอายุแล้ว', $this->sessionError('code'));
        $this->assertNull(session('registration'));
    }

    public function test_a_list_with_nothing_selectable_says_so_and_has_no_submit_button(): void
    {
        $this->store->accountStates = [
            self::fingerprintOf('1234567890') => AccountState::Held,
            self::fingerprintOf('0987654321') => AccountState::Registered,
        ];
        $this->reachAccountSelection();

        $this->get('/accounts')->assertOk()
            ->assertSee('ไม่มีบัญชีในรายการนี้ที่ลงทะเบียนได้')
            ->assertDontSee('id="accounts-submit"', false)
            ->assertSee('ยกเลิกและเริ่มใหม่');
    }

    public function test_a_new_bank_login_drops_the_states_of_the_previous_list(): void
    {
        $this->reachAccountSelection();
        $this->assertNotNull(session('registration.account_states'));

        $this->login()->assertRedirect('/approve');

        $this->assertNull(session('registration.account_states'));
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->assertNull(session('registration.account_states'), 'a fresh list has fresh tokens and no states yet');
    }

    public function test_a_forged_state_in_the_form_is_ignored(): void
    {
        $this->store->accountStates = [self::fingerprintOf('1234567890') => AccountState::Held];
        $this->reachAccountSelection();

        $this->from('/accounts')->post('/accounts', [
            'list' => session('registration.list_nonce'),
            'account' => $this->tokenFor(0),
            'states' => [$this->tokenFor(0) => 'new'],
        ])->assertRedirect('/accounts');

        $this->assertSame('บัญชีนี้ถูกระงับ ติดต่อผู้ดูแล', $this->sessionError('account'));
        $this->assertSame([], $this->store->registrations);
    }

    public function test_viewing_the_account_list_is_rate_limited_per_client(): void
    {
        $this->store->accountStatesUnavailable = true;
        $this->reachAccountSelection();
        $calls = count($this->store->accountStateCalls);

        for ($i = 1; $i < 30; $i++) {
            $this->get('/accounts')->assertOk();
        }
        $this->get('/accounts')->assertStatus(429);

        $this->assertSame($calls + 29, count($this->store->accountStateCalls), 'a throttled view never reaches the database');
    }

    private function reachAccountSelection(): void
    {
        FakeBank::fake();
        $this->post('/code', ['code' => self::CODE]);
        $this->login();
        $this->postJson('/approve/status')->assertJson(['state' => 'approved']);
        $this->get('/accounts')->assertOk();
    }

    private function tokenFor(int $index): string
    {
        return session('registration.accounts')[$index]['token'];
    }

    /**
     * @param  int  $index  position in the list the bank returned
     */
    private function selectAccount(int $index): TestResponse
    {
        return $this->post('/accounts', [
            'list' => session('registration.list_nonce'),
            'account' => $this->tokenFor($index),
        ]);
    }

    private function login(): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])->post('/login', $this->loginForm());
    }

    /**
     * @return array<string, string>
     */
    private function loginForm(): array
    {
        return ['username' => 'alice', 'password' => self::PASSWORD, 'webhook_url' => self::WEBHOOK];
    }

    /**
     * Sessions use JSON serialization, so after a request the error bag may
     * be held in its array form.
     */
    private function sessionError(string $key): string
    {
        $errors = session('errors');

        return $errors instanceof ViewErrorBag
            ? (string) $errors->first($key)
            : (string) ($errors['default']['messages'][$key][0] ?? '');
    }

    private function assertPasswordNotInSession(): void
    {
        $this->assertStringNotContainsString(self::PASSWORD, serialize(session()->all()));
        $this->assertStringNotContainsString(self::PASSWORD, json_encode(session()->all(), JSON_UNESCAPED_UNICODE));
    }

    private function assertNoSecretsLogged(): void
    {
        $all = implode("\n", $this->logLines);
        foreach ([self::PASSWORD, 'session-token-xyz', '1234567890', '0987654321', self::CODE, 'ORG-9'] as $secret) {
            $this->assertStringNotContainsString($secret, $all);
        }
    }
}
