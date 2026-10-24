<?php

namespace Tests\Feature;

use App\Registration\BankLoginBudget;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Filesystem\Filesystem;
use Mockery;
use Tests\TestCase;

final class BankLoginBudgetTest extends TestCase
{
    private function settings(int $perMinute, int $perHour = 200): WrapbizSettings
    {
        config(['wrapbiz.bank_logins_per_minute' => (string) $perMinute, 'wrapbiz.bank_logins_per_hour' => (string) $perHour]);

        return WrapbizSettings::fromArray(config('wrapbiz'));
    }

    public function test_grants_up_to_the_per_minute_and_per_hour_caps(): void
    {
        $store = new ArrayStore;
        $limiter = new RateLimiter(new Repository($store));

        $budget = new BankLoginBudget($limiter, $store, $this->settings(3));
        $this->assertSame([true, true, true, false, false], array_map(fn () => $budget->tryConsume(), range(1, 5)));

        $hourly = new BankLoginBudget(new RateLimiter(new Repository($other = new ArrayStore)), $other, $this->settings(10, 2));
        $this->assertSame([true, true, false], array_map(fn () => $hourly->tryConsume(), range(1, 3)));
    }

    public function test_a_lock_that_cannot_be_taken_refuses_the_login(): void
    {
        $lock = Mockery::mock(Lock::class);
        $lock->shouldReceive('betweenBlockedAttemptsSleepFor')->andReturnSelf();
        $lock->shouldReceive('block')->andThrow(new LockTimeoutException);
        $locks = Mockery::mock(LockProvider::class);
        $locks->shouldReceive('lock')->andReturn($lock);
        $limiter = new RateLimiter(new Repository(new ArrayStore));

        $this->assertFalse((new BankLoginBudget($limiter, $locks, $this->settings(5)))->tryConsume());
        $this->assertSame(0, (int) $limiter->attempts('bank-login-global:minute'));
    }

    /**
     * SEC-R1-10: parallel web workers sharing a file cache must not all pass
     * the check before any of them records its hit.
     */
    public function test_parallel_workers_never_exceed_the_cap(): void
    {
        $directory = sys_get_temp_dir().'/wrapbiz-budget-'.bin2hex(random_bytes(6));
        $startSignal = $directory.'/start';
        mkdir($directory);
        $workers = [];

        try {
            for ($i = 0; $i < 16; $i++) {
                $process = proc_open(
                    [PHP_BINARY, base_path('tests/Support/budget-worker.php'), $directory.'/cache', $startSignal, '5'],
                    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                    $pipes,
                );
                $this->assertIsResource($process);
                $workers[] = [$process, $pipes];
            }
            usleep(300_000);
            touch($startSignal);

            $granted = 0;
            foreach ($workers as [$process, $pipes]) {
                $output = stream_get_contents($pipes[1]);
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                $this->assertSame(0, proc_close($process), (string) $errors);
                $this->assertContains($output, ['0', '1']);
                $granted += (int) $output;
            }

            $this->assertSame(5, $granted);
        } finally {
            (new Filesystem)->deleteDirectory($directory);
        }
    }
}
