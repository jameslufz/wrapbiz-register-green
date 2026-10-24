<?php

namespace Tests\Feature;

use App\Kbiz\ApprovalStatus;
use App\Kbiz\BankException;
use App\Kbiz\BankFailure;
use App\Kbiz\KbizClient;
use App\Kbiz\KbizConfig;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\Client\Events\ConnectionFailed;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/**
 * Runs KbizClient through the real curl handler (Http::fake bypasses it)
 * against a local php -S server, so the streaming size limit, redirect
 * policy and connect-retry rules are tested where they actually apply.
 */
final class KbizTransportTest extends TestCase
{
    private static ?Process $server = null;

    private static int $port = 0;

    private static string $hitLog = '';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$port = self::freePort();
        self::$hitLog = tempnam(sys_get_temp_dir(), 'transport-bank-');
        self::$server = new Process(
            [PHP_BINARY, '-S', '127.0.0.1:'.self::$port, dirname(__DIR__).'/Support/transport-bank.php'],
            env: ['TRANSPORT_BANK_LOG' => self::$hitLog],
        );
        self::$server->start();

        $deadline = microtime(true) + 5;
        while (@fsockopen('127.0.0.1', self::$port) === false) {
            if (microtime(true) > $deadline) {
                self::fail('transport bank did not start');
            }
            usleep(50_000);
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop(1);
        self::$server = null;
        @unlink(self::$hitLog);

        parent::tearDownAfterClass();
    }

    protected function setUp(): void
    {
        parent::setUp();

        file_put_contents(self::$hitLog, '');
        Http::preventStrayRequests(false);
        $this->routeBankTo(self::$port);
    }

    public function test_a_normal_response_passes(): void
    {
        $this->assertSame(ApprovalStatus::Pending, $this->approvalStatusFrom('/ok'));
    }

    public function test_a_body_that_grows_past_the_limit_is_cut_off_while_streaming(): void
    {
        $memoryBefore = memory_get_peak_usage(true);

        $this->assertFailure(BankFailure::UnexpectedResponse, fn () => $this->approvalStatusFrom('/streamed-oversize'));
        $this->assertLessThan(16 * 1024 * 1024, memory_get_peak_usage(true) - $memoryBefore, '64 MiB body was not buffered');
    }

    public function test_a_declared_oversize_body_is_refused_at_the_headers(): void
    {
        $started = microtime(true);

        $this->assertFailure(BankFailure::UnexpectedResponse, fn () => $this->approvalStatusFrom('/declared-oversize'));
        $this->assertLessThan(3, microtime(true) - $started, 'did not wait for the declared body');
    }

    public function test_a_compressed_body_cannot_inflate_past_the_limit(): void
    {
        $memoryBefore = memory_get_peak_usage(true);

        $this->assertFailure(BankFailure::UnexpectedResponse, fn () => $this->approvalStatusFrom('/gzip-bomb'));
        $this->assertLessThan(16 * 1024 * 1024, memory_get_peak_usage(true) - $memoryBefore);
    }

    public function test_redirects_are_not_followed_by_the_real_handler(): void
    {
        $this->assertFailure(BankFailure::Redirected, fn () => $this->approvalStatusFrom('/redirect'));
        $this->assertSame(['/redirect'], $this->hits());
    }

    public function test_refused_connections_are_retried_for_repeatable_steps_only(): void
    {
        $this->routeBankTo(self::freePort());
        $failures = 0;
        Event::listen(ConnectionFailed::class, function () use (&$failures) {
            $failures++;
        });

        $this->assertFailure(BankFailure::Unreachable, fn () => $this->approvalStatusFrom('/ok'));
        $this->assertSame(3, $failures, 'approval polling retried');

        $failures = 0;
        $this->assertFailure(BankFailure::Unreachable, fn () => $this->app->make(KbizClient::class)->completeLogin(new CookieJar));
        $this->assertSame(1, $failures, 'one-time qr confirmation sent once');
    }

    private function approvalStatusFrom(string $path): ApprovalStatus
    {
        config(['kbiz.apis.3.path' => $path]);
        $this->app->forgetInstance(KbizConfig::class);

        return $this->app->make(KbizClient::class)->approvalStatus(new CookieJar);
    }

    private function routeBankTo(int $port): void
    {
        Http::globalRequestMiddleware(fn (RequestInterface $request) => $request->withUri(
            $request->getUri()->withScheme('http')->withHost('127.0.0.1')->withPort($port),
        ));
    }

    /**
     * @return list<string>
     */
    private function hits(): array
    {
        return array_values(array_filter(explode("\n", (string) file_get_contents(self::$hitLog))));
    }

    private function assertFailure(BankFailure $failure, callable $call): void
    {
        try {
            $call();
            $this->fail("expected {$failure->value}");
        } catch (BankException $exception) {
            $this->assertSame($failure, $exception->failure);
        }
    }

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
    }
}
