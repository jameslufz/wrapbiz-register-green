<?php

namespace Tests\Feature;

use App\Kbiz\BankException;
use App\Kbiz\BankFailure;
use App\Kbiz\KbizClient;
use App\Wrapbiz\CodeStatus;
use App\Wrapbiz\RegistrationStore;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\TooManyRedirectsException;
use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeBank;
use Tests\Support\RecordingStore;
use Tests\TestCase;

/**
 * The security and QA reviewers' proof-of-concept scenarios, kept as
 * regressions with the behaviour they now must show.
 */
final class ReviewFindingsTest extends TestCase
{
    private const string CODE = 'reg-code-0123456789abcdef';

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

    public function test_one_code_no_longer_gives_unlimited_bank_logins_by_rotating_ipv6_addresses(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])->post('/code', ['code' => self::CODE])->assertRedirect('/login');

        for ($i = 1; $i <= 60; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::'.dechex($i)])
                ->from('/login')
                ->post('/login', ['username' => "victim{$i}", 'password' => "guess{$i}", 'webhook_url' => 'https://hooks.example.com/x']);
        }

        $submits = Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count();
        $this->assertSame(5, $submits, 'one /64 shares the per-IP limit');
    }

    public function test_rotating_across_many_networks_is_stopped_by_the_code_lock(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('<p>bad password</p>')]);
        $this->post('/code', ['code' => self::CODE]);

        for ($i = 1; $i <= 60; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => "2001:db8:{$i}::1"])
                ->from('/login')
                ->post('/login', ['username' => "victim{$i}", 'password' => "guess{$i}", 'webhook_url' => 'https://hooks.example.com/x']);
        }

        $this->assertSame(RecordingStore::LOCK_AFTER, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count());
        $this->assertSame(CodeStatus::Locked, $this->store->statusOf(self::CODE));
    }

    /**
     * SEC round 2 PoC: a 3xx (or 4xx/5xx) answer to the credential submit
     * used to be free, so rotating networks gave unlimited guesses. Every
     * answer that is not a QR challenge now counts (lead decision A8).
     */
    #[DataProvider('nonQrAnswers')]
    public function test_non_qr_answers_to_the_credentials_are_capped_by_the_code_lock(int $status): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => Http::response('', $status, ['Location' => 'https://bank.test/err?x=1'])]);
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])->post('/code', ['code' => self::CODE])->assertRedirect('/login');

        for ($i = 1; $i <= 30; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => sprintf('2001:db8:%x::1', $i)])->from('/login')
                ->post('/login', ['username' => "u{$i}", 'password' => "p{$i}", 'webhook_url' => 'https://hooks.example.com/x']);
        }

        $this->assertSame(RecordingStore::LOCK_AFTER, Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count());
        $this->assertSame(0, Http::recorded(fn (Request $r) => str_contains($r->url(), '/err'))->count(), 'redirects are never followed');
        $this->assertSame(CodeStatus::Locked, $this->store->statusOf(self::CODE));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function nonQrAnswers(): iterable
    {
        foreach ([200, 302, 401, 429, 503] as $status) {
            yield (string) $status => [$status];
        }
    }

    public function test_transfer_errors_carrying_urls_never_reach_the_logs(): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => function () {
            throw new TooManyRedirectsException(
                'Will not follow more than 5 redirects https://bank.test/secret/path?tok=SECRETTOKEN',
                new PsrRequest('POST', 'https://bank.test/secret/path?tok=SECRETTOKEN'),
                new PsrResponse(302),
            );
        }]);
        $this->post('/code', ['code' => self::CODE]);

        $this->from('/login')
            ->post('/login', ['username' => 'u', 'password' => 'p', 'webhook_url' => 'https://hooks.example.com/x'])
            ->assertRedirect('/login');

        $this->assertStringNotContainsString('SECRETTOKEN', implode("\n", $this->logLines));
        $this->assertSame([], $this->store->failedLogins);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function oddCodes(): iterable
    {
        yield 'inner space' => ['reg-code 0123456789abcdef'];
        yield 'fullwidth' => ['ｒeg-code-0123456789abcdef'];
        yield 'embedded null byte' => ["reg-code-\0-0123456789abcdef"];
        yield 'array' => [['reg-code-0123456789abcdef']];
        yield 'too long' => [str_repeat('z', 257)];
    }

    #[DataProvider('oddCodes')]
    public function test_odd_code_input_is_refused_cleanly(mixed $code): void
    {
        $this->from('/')->post('/code', ['code' => $code])->assertRedirect('/')->assertSessionHasErrors('code');
        $this->assertNull(session('registration'));
    }

    public function test_surrounding_whitespace_and_invisible_characters_are_trimmed(): void
    {
        foreach (['  '.self::CODE."\t\n", "\u{200B}".self::CODE, "\u{00A0}".self::CODE] as $i => $code) {
            $this->flushSession();
            $this->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])->post('/code', ['code' => $code])->assertRedirect('/login');
        }
    }

    /**
     * @return iterable<string, array{mixed, int}>
     */
    public static function malformedApprovalResponses(): iterable
    {
        yield 'json scalar' => ['"YES"', 200];
        yield 'json list' => ['[1,2]', 200];
        yield 'html instead of json' => ['<html>maintenance</html>', 200];
        yield 'state as number' => [(string) json_encode(['k_wrap' => ['k_state' => 1]]), 200];
        yield 'deeply nested json' => [str_repeat('[', 600).str_repeat(']', 600), 200];
        yield 'no content' => ['', 204];
    }

    #[DataProvider('malformedApprovalResponses')]
    public function test_malformed_bank_responses_are_unexpected_not_crashes(string $body, int $status): void
    {
        FakeBank::fake([FakeBank::BASE_URL.'/p/three' => Http::response($body, $status)]);

        try {
            $this->app->make(KbizClient::class)->approvalStatus(new CookieJar);
            $this->fail('expected a bank failure');
        } catch (BankException $exception) {
            $this->assertSame(BankFailure::UnexpectedResponse, $exception->failure);
        }
    }
}
