<?php

namespace Tests\Feature;

use App\Kbiz\KbizConfigException;
use App\Providers\AppServiceProvider;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use ReflectionProperty;
use Tests\TestCase;

/**
 * Tests run as console, where the provider skips the web-only checks; these
 * boot it as the web server would.
 */
final class WebBootTest extends TestCase
{
    protected function tearDown(): void
    {
        TrustProxies::flushState();

        parent::tearDown();
    }

    private function bootAsWebServer(): void
    {
        (new ReflectionProperty($this->app, 'isRunningInConsole'))->setValue($this->app, false);
        $this->app->forgetInstance(WrapbizSettings::class);
        (new AppServiceProvider($this->app))->boot();
    }

    public function test_sec_wildcard_trusted_proxies_stop_the_site_from_serving(): void
    {
        foreach (['*', '**', 'REMOTE_ADDR', '0.0.0.0/0', '::/0', '::/32', '::ffff:0:0/96', '10.0.0.0/8'] as $proxies) {
            config(['wrapbiz.trusted_proxies' => $proxies]);

            try {
                $this->bootAsWebServer();
                $this->fail("{$proxies} must be refused");
            } catch (KbizConfigException $exception) {
                $this->assertStringStartsWith('TRUSTED_PROXIES', $exception->getMessage());
            }
        }
    }

    public function test_forwarded_client_ip_is_only_believed_from_a_listed_proxy(): void
    {
        config(['wrapbiz.trusted_proxies' => '10.0.0.0/16']);
        $this->bootAsWebServer();
        Route::get('/__client-ip', fn (Request $request) => $request->ip());

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.50'])
            ->get('/__client-ip')->assertSee('203.0.113.50');
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.77'])
            ->get('/__client-ip')->assertSee('198.51.100.1')->assertDontSee('203.0.113.77');
    }

    public function test_an_incomplete_environment_fails_fast_on_web_boot(): void
    {
        config(['kbiz.base_url' => null]);

        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessage('KBIZ_BASE_URL is not set.');
        $this->bootAsWebServer();
    }

    public function test_an_ipv4_mapped_client_is_not_believed_through_any_accepted_proxy_range(): void
    {
        config(['wrapbiz.trusted_proxies' => '10.0.0.0/16,2001:db8::/32,::1']);
        $this->bootAsWebServer();
        Route::get('/__client-ip', fn (Request $request) => $request->ip());

        foreach (['::ffff:198.51.100.1', '198.51.100.1', '::198.51.100.1'] as $client) {
            $this->withServerVariables(['REMOTE_ADDR' => $client, 'HTTP_X_FORWARDED_FOR' => '203.0.113.77'])
                ->get('/__client-ip')->assertDontSee('203.0.113.77');
        }
    }

    public function test_an_unencrypted_remote_database_stops_the_site_from_serving(): void
    {
        config(['database.connections.wrapbiz.host' => 'db.example.com', 'database.connections.wrapbiz.sslmode' => 'disable']);

        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessageMatches('/^WRAPBIZ_DB_SSLMODE /');
        $this->bootAsWebServer();
    }
}
