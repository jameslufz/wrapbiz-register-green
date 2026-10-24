<?php

namespace Tests\Integration;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ViewErrorBag;
use Tests\Support\FakeBank;
use Tests\TestCase;

/**
 * One competitor of WrapbizDatabaseTest::test_parallel_logins_on_one_code_reach_the_bank_at_most_five_times:
 * its own session submits one wrong login for the shared code at the
 * shared start time and reports what happened on STDERR. Skipped unless
 * that test started it.
 */
final class ParallelLoginRacerTest extends TestCase
{
    public const string RESULT_PREFIX = 'WRAPBIZ_RACE_RESULT=';

    public function test_one_racer(): void
    {
        $code = getenv('WRAPBIZ_RACE_CODE');
        if (! is_string($code) || $code === '') {
            $this->markTestSkipped('Started only by the parallel login regression test.');
        }

        config(['database.connections.wrapbiz' => array_merge(config('database.connections.wrapbiz'), [
            'url' => null,
            'host' => getenv('WRAPBIZ_RACE_DB_HOST'),
            'port' => getenv('WRAPBIZ_RACE_DB_PORT'),
            'database' => getenv('WRAPBIZ_RACE_DB_DATABASE'),
            'username' => getenv('WRAPBIZ_RACE_DB_USERNAME'),
            'password' => getenv('WRAPBIZ_RACE_DB_PASSWORD'),
            'sslmode' => 'disable',
        ])]);
        DB::purge('wrapbiz');
        // Long enough that every racer reserves while the others are still waiting on the bank.
        FakeBank::fake([FakeBank::BASE_URL.'/p/two/submit' => function () {
            usleep(1_500_000);

            return Http::response('<p>bad password</p>');
        }]);

        $ip = (string) getenv('WRAPBIZ_RACE_IP');
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->post('/code', ['code' => $code])->assertRedirect('/login');
        $startAt = (float) getenv('WRAPBIZ_RACE_START');
        while (microtime(true) < $startAt) {
            usleep(500);
        }
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->from('/login')
            ->post('/login', ['username' => 'u', 'password' => 'wrong', 'webhook_url' => 'https://hooks.example.com/race']);

        $submits = Http::recorded(fn (Request $r) => FakeBank::sentTo($r, '/p/two/submit'))->count();
        fwrite(STDERR, self::RESULT_PREFIX.json_encode(['submits' => $submits, 'errors' => $this->errors()], JSON_UNESCAPED_UNICODE)."\n");
        $this->assertLessThanOrEqual(1, $submits);
    }

    /**
     * @return array<string, string>
     */
    private function errors(): array
    {
        $errors = session('errors');
        if ($errors instanceof ViewErrorBag) {
            return array_map(fn (array $messages) => (string) $messages[0], $errors->getBag('default')->toArray());
        }

        return array_map(fn (array $messages) => (string) $messages[0], $errors['default']['messages'] ?? []);
    }
}
