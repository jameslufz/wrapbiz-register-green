<?php

namespace App\Providers;

use App\Kbiz\KbizConfig;
use App\Kbiz\KbizConfigException;
use App\Registration\BankLoginBudget;
use App\Security\AccountFingerprinter;
use App\Security\CredentialSealer;
use App\Security\DnsResolver;
use App\Security\IpHasher;
use App\Security\RateLimitKey;
use App\Security\SystemDnsResolver;
use App\Wrapbiz\DatabaseTlsPolicy;
use App\Wrapbiz\PinnedSessionPostgresConnector;
use App\Wrapbiz\PostgresRegistrationStore;
use App\Wrapbiz\RegistrationStore;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Cache\RateLimiter as CacheRateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\HttpFoundation\Response;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(KbizConfig::class, fn () => KbizConfig::fromArray(config('kbiz')));
        $this->app->singleton(WrapbizSettings::class, fn () => WrapbizSettings::fromArray(config('wrapbiz')));

        $this->app->bind(DnsResolver::class, SystemDnsResolver::class);
        $this->app->bind(CredentialSealer::class, fn ($app) => new CredentialSealer($app->make(WrapbizSettings::class)->sealPublicKey));
        $this->app->bind(AccountFingerprinter::class, fn ($app) => new AccountFingerprinter($app->make(WrapbizSettings::class)->fingerprintKey));
        $this->app->bind(IpHasher::class, fn ($app) => new IpHasher($app->make(WrapbizSettings::class)->ipHashKey));
        $this->app->bind('db.connector.pgsql', PinnedSessionPostgresConnector::class);
        $this->app->bind(RegistrationStore::class, function () {
            // Web requests are checked at boot; console and queue code reach
            // the store without that check.
            DatabaseTlsPolicy::assertSafe((array) config('database.connections.wrapbiz'));

            return new PostgresRegistrationStore(DB::connection('wrapbiz'));
        });
        $this->app->bind(BankLoginBudget::class, fn ($app) => new BankLoginBudget(
            $app->make(CacheRateLimiter::class),
            self::limiterLocks($app),
            $app->make(WrapbizSettings::class),
        ));
    }

    /**
     * The budget's lock must live in the same store as the rate limiter's
     * counters, or it would not serialise their updates.
     */
    private static function limiterLocks(Application $app): LockProvider
    {
        $store = $app->make('cache')->driver($app['config']->get('cache.limiter'))->getStore();
        if (! $store instanceof LockProvider) {
            throw new KbizConfigException('CACHE_STORE must be a cache store that supports atomic locks (file, redis, database, memcached).');
        }

        return $store;
    }

    public function boot(): void
    {
        if ($this->app->isProduction()) {
            config(['app.debug' => false]);
        }

        $this->configureRateLimits();

        // Fail fast on every web request if env is incomplete or unsafe; the
        // message names the variable only. Console uses
        // `php artisan wrapbiz:check-config`, which reports the same problems.
        if (! $this->app->runningInConsole()) {
            $this->app->make(KbizConfig::class);
            DatabaseTlsPolicy::assertSafe((array) config('database.connections.wrapbiz'));
            $settings = $this->app->make(WrapbizSettings::class);
            if ($settings->trustedProxies !== []) {
                TrustProxies::at($settings->trustedProxies);
            }
        }
    }

    private function configureRateLimits(): void
    {
        $formTooMany = fn (string $field) => fn (Request $request, array $headers): Response => back()
            ->withInput($request->except(['password', 'code']))
            ->withErrors([$field => 'ลองหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่'])
            ->withHeaders($headers);

        $client = fn (Request $request) => RateLimitKey::forIp($request->ip());

        RateLimiter::for('register-code', fn (Request $request) => [
            Limit::perMinute(5)->by('code-m:'.$client($request))->response($formTooMany('code')),
            Limit::perHour(30)->by('code-h:'.$client($request))->response($formTooMany('code')),
        ]);

        RateLimiter::for('bank-login', fn (Request $request) => [
            Limit::perMinute(5)->by('login-m:'.$client($request))->response($formTooMany('login')),
            Limit::perHour(20)->by('login-h:'.$client($request))->response($formTooMany('login')),
        ]);

        RateLimiter::for('approval-poll', fn (Request $request) => Limit::perMinute(60)
            ->by('poll:'.$client($request))
            ->response(fn (Request $request, array $headers): Response => response()->json(
                ['state' => 'throttled', 'message' => 'ตรวจสอบสถานะถี่เกินไป ระบบจะลองใหม่อัตโนมัติ'],
                429,
                $headers,
            )));

        // A view asks the database for the listed accounts' states until one ask succeeds.
        RateLimiter::for('accounts-view', fn (Request $request) => Limit::perMinute(30)->by('accounts:'.$client($request)));

        RateLimiter::for('register-submit', fn (Request $request) => Limit::perMinute(10)
            ->by('submit:'.$client($request))
            ->response($formTooMany('accounts')));
    }
}
