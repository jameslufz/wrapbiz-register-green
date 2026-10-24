<?php

namespace Tests\Feature;

use App\Kbiz\KbizClient;
use App\Kbiz\KbizConfig;
use App\Registration\BankLoginBudget;
use App\Wrapbiz\AttemptReservation;
use Carbon\CarbonInterval;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Tests\Support\FakeBank;
use Tests\TestCase;

/**
 * SEC-R3-03 / BUG-R4-02: a /login request holds one of the register code's
 * attempt reservations. If the request could outlive the reservation, the
 * database would hand the slot to another login while these credentials
 * may still reach the bank, and more than five could be tried.
 */
final class LoginDurationBoundTest extends TestCase
{
    private const string QR_PATH = '/img/qr.png';

    public function test_the_slowest_possible_bank_login_ends_before_its_attempt_reservation_expires(): void
    {
        config(['kbiz.timeout_seconds' => (string) KbizConfig::MAX_TIMEOUT_SECONDS]);
        $this->app->forgetInstance(KbizConfig::class);
        $timeout = $this->app->make(KbizConfig::class)->timeoutSeconds;

        $slept = 0.0;
        Sleep::fake();
        Sleep::whenFakingSleep(function (CarbonInterval $duration) use (&$slept) {
            $slept += $duration->totalMicroseconds / 1_000_000;
        });

        $attempts = [];
        $connectFailsUntilLastAttempt = function (string $path, callable $answer) use (&$attempts) {
            return function (Request $request) use ($path, $answer, &$attempts) {
                $attempts[$path] = ($attempts[$path] ?? 0) + 1;

                return $attempts[$path] < KbizClient::CONNECT_ATTEMPTS
                    ? Create::rejectionFor(new ConnectException('cURL error 28: connect timed out', new PsrRequest($request->method(), $request->url())))
                    : $answer();
            };
        };
        FakeBank::fake([
            FakeBank::BASE_URL.'/p/one' => $connectFailsUntilLastAttempt('/p/one', fn () => Http::response(FakeBank::loginPage())),
            FakeBank::BASE_URL.'/p/two/submit' => function () use (&$attempts) {
                $attempts['/p/two/submit'] = ($attempts['/p/two/submit'] ?? 0) + 1;

                return Http::response(FakeBank::qrPage(self::QR_PATH));
            },
            FakeBank::BASE_URL.self::QR_PATH => $connectFailsUntilLastAttempt(self::QR_PATH, fn () => Http::response(
                (string) base64_decode(FakeBank::QR_PNG_BASE64, true),
                200,
                ['Content-Type' => 'image/png'],
            )),
        ]);

        $this->app->make(KbizClient::class)->startLogin(new CookieJar, 'u', 'p');

        // Every retryable request was retried as often as the client ever
        // retries; the credential submit is never retried.
        $this->assertSame(['/p/one' => KbizClient::CONNECT_ATTEMPTS, '/p/two/submit' => 1, self::QR_PATH => KbizClient::CONNECT_ATTEMPTS], $attempts);

        // A retried attempt never connected, so it ended within the connect
        // timeout; the attempt that connected may run the whole timeout.
        $requests = count($attempts);
        $failedConnects = array_sum($attempts) - $requests;
        $connectTimeout = min(KbizClient::MAX_CONNECT_TIMEOUT_SECONDS, $timeout);
        $worstCase = BankLoginBudget::LOCK_WAIT_SECONDS
            + $failedConnects * $connectTimeout
            + $slept
            + $requests * $timeout;

        $this->assertSame(45, $timeout);
        $this->assertSame(4, $failedConnects);
        $this->assertEqualsWithDelta(4 * KbizClient::CONNECT_RETRY_DELAY_MS / 1000, $slept, 0.001);
        $this->assertLessThan(AttemptReservation::TTL_SECONDS, $worstCase, "worst-case /login takes {$worstCase}s");
    }

    public function test_a_longer_timeout_than_the_bound_allows_is_refused(): void
    {
        $this->expectExceptionMessage('KBIZ_TIMEOUT_SECONDS must be a whole number of seconds between 1 and 45.');

        KbizConfig::fromArray([...FakeBank::config(), 'timeout_seconds' => (string) (KbizConfig::MAX_TIMEOUT_SECONDS + 1)]);
    }
}
