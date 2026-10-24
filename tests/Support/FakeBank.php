<?php

namespace Tests\Support;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/**
 * Placeholder bank used by tests. Host, paths, header names, keys and
 * selectors are invented; they must never resemble the real bank's.
 */
final class FakeBank
{
    public const string BASE_URL = 'https://bank.test';

    public const string QR_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

    /**
     * @return array<string, mixed>
     */
    public static function config(): array
    {
        $json = fn (array $value) => json_encode($value, JSON_THROW_ON_ERROR);

        return [
            'base_url' => self::BASE_URL,
            'timeout_seconds' => 5,
            'apis' => [
                1 => ['path' => '/p/one', 'headers' => $json(['X-Test-Agent' => 'test-agent'])],
                2 => [
                    'path' => '/p/two/submit',
                    'headers' => $json(['X-Test-Agent' => 'test-agent']),
                    'fields' => $json([
                        'login_name' => 'k_user', 'login_secret' => 'k_pass', 'login_token' => 'k_token',
                        'command' => 'k_cmd', 'ui_locale' => 'k_locale', 'customer_type' => 'k_ctype',
                        'touch_points' => 'k_touch', 'app_mode' => 'k_app',
                    ]),
                    'values' => $json([
                        'command' => 'go', 'ui_locale' => 'xx', 'customer_type' => 'ct-x', 'touch_points' => 7, 'app_mode' => 9,
                    ]),
                ],
                3 => [
                    'path' => '/p/three',
                    'fields' => $json(['approval_state' => 'k_wrap.k_state']),
                    'values' => $json(['state_approved' => 'YES', 'state_rejected' => 'NO']),
                ],
                4 => [
                    'path' => '/p/four',
                    'fields' => $json(['qr_timestamp' => 'k_ts', 'error_text' => 'k_err', 'ui_locale' => 'k_locale', 'command' => 'k_cmd']),
                    'values' => $json(['error_text' => 'err-x', 'ui_locale' => 'xx', 'command' => 'go']),
                ],
                5 => ['path' => '/p/five'],
                6 => [
                    'path' => '/p/six',
                    'fields' => $json([
                        'handoff_token' => 'k_handoff', 'session_token_header' => 'x-test-session',
                        'profile' => 'k_data.k_profiles.0', 'user_ref' => 'k_uref', 'org_id' => 'k_org', 'customer_type' => 'k_ctype',
                    ]),
                ],
                7 => [
                    'path' => '/p/seven',
                    'headers' => $json(['x-test-app' => 'tester']),
                    'fields' => $json([
                        'customer_type' => 'k_ctype', 'owner_id' => 'k_owner', 'user_ref_header' => 'x-test-uref',
                        'session_user_ref_header' => 'x-test-suref', 'session_auth_header' => 'x-test-auth',
                        'account_list' => 'k_data.k_accounts', 'account_number' => 'k_no', 'account_kind' => 'k_kind',
                        'account_filter' => 'k_filter', 'balance_flag' => 'k_bal', 'response_language' => 'k_lang',
                        'nickname_kind' => 'k_nick', 'owner_kind' => 'k_okind',
                    ]),
                    'values' => $json([
                        'account_filter' => 'A,B', 'balance_flag' => 'bal-x', 'response_language' => 'xx', 'nickname_kind' => 'nick', 'owner_kind' => 'org',
                    ]),
                ],
            ],
            'selectors' => [
                1 => '//input[@name="k_token"]/@value',
                2 => '//img[@id="k-qr"]/@src',
                3 => '//input[@name="k_deadline"]/@value',
                4 => '#k-confirmed#',
                5 => '#k_handoff=([A-Za-z0-9%]+)#',
            ],
        ];
    }

    public static function loginPage(string $token = 'tok-123'): string
    {
        return '<html><body><form><input type="hidden" name="k_token" value="'.$token.'"></form></body></html>';
    }

    public static function qrPage(?string $src = null, string $deadline = '120'): string
    {
        $src ??= 'data:image/png;base64,'.self::QR_PNG_BASE64;

        return '<html><body><img id="k-qr" src="'.$src.'"><input name="k_deadline" value="'.$deadline.'"></body></html>';
    }

    /**
     * Starts from a fresh HTTP factory: stacked fakes would otherwise keep
     * answering with the first matching stub. Unmatched URLs fail the test.
     *
     * @param  array<string, mixed>  $overrides  url => response, replacing the happy-path response
     */
    public static function fake(array $overrides = []): Factory
    {
        Http::swap(new Factory(app('events')));

        $responses = [
            self::BASE_URL.'/p/one' => Http::response(self::loginPage(), 200, ['Set-Cookie' => 'BANKSID=abc; Path=/; Secure']),
            self::BASE_URL.'/p/two/submit' => Http::response(self::qrPage()),
            self::BASE_URL.'/p/three' => Http::response(['k_wrap' => ['k_state' => 'YES']]),
            self::BASE_URL.'/p/four' => Http::response('<script>k-confirmed</script>'),
            self::BASE_URL.'/p/five' => Http::response('<script>go("?k_handoff=hand%2Doff")</script>'),
            self::BASE_URL.'/p/six' => Http::response(
                ['k_data' => ['k_profiles' => [['k_uref' => 'U-1', 'k_org' => 'ORG-9', 'k_ctype' => 'C']]]],
                200,
                ['x-test-session' => 'session-token-xyz'],
            ),
            self::BASE_URL.'/p/seven' => Http::response(['k_data' => ['k_accounts' => [
                ['k_no' => '1234567890', 'k_kind' => 'SA', 'k_balance' => '999.00', 'k_name' => 'Someone'],
                ['k_no' => '098-7-65432-1', 'k_kind' => 'CA'],
                ['k_no' => '1234567890', 'k_kind' => 'SA'],
                ['k_no' => 'not-a-number', 'k_kind' => 'XX'],
            ]]]),
        ];

        $factory = Http::fake(array_merge($responses, $overrides));
        Http::preventStrayRequests();

        return $factory;
    }

    public static function sentTo(Request $request, string $path): bool
    {
        return parse_url($request->url(), PHP_URL_PATH) === $path;
    }
}
