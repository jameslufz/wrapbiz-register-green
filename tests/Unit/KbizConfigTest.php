<?php

namespace Tests\Unit;

use App\Kbiz\KbizConfig;
use App\Kbiz\KbizConfigException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FakeBank;

final class KbizConfigTest extends TestCase
{
    public function test_loads_a_complete_configuration(): void
    {
        $config = KbizConfig::fromArray(FakeBank::config());

        $this->assertSame('https://bank.test', $config->baseUrl);
        $this->assertSame('bank.test', $config->host);
        $submit = $config->step('login_submit');
        $this->assertSame('/p/two/submit', $submit->path);
        $this->assertSame('k_pass', $submit->field('login_secret'));
        $this->assertSame(['X-Test-Agent' => 'test-agent'], $submit->headers);
        $this->assertSame(
            ['k_cmd' => 'go', 'k_locale' => 'xx', 'k_ctype' => 'ct-x', 'k_touch' => '7', 'k_app' => '9'],
            $submit->constantFields(),
        );
        $this->assertSame('YES', $config->step('approval_status')->value('state_approved'));
        $this->assertSame('https://bank.test/p/one', $config->url($config->step('login_page')));
        $this->assertSame('#k-confirmed#', $config->selector('qr_confirmed'));
    }

    public function test_trailing_slash_on_base_url_is_removed(): void
    {
        $raw = FakeBank::config();
        $raw['base_url'] = 'https://bank.test/';

        $this->assertSame('https://bank.test', KbizConfig::fromArray($raw)->baseUrl);
    }

    public function test_optional_headers_default_to_empty(): void
    {
        $this->assertSame([], KbizConfig::fromArray(FakeBank::config())->step('approval_status')->headers);
    }

    /**
     * @return iterable<string, array{0: callable(array): array, 1: string}>
     */
    public static function brokenConfigurations(): iterable
    {
        yield 'missing base url' => [fn (array $c) => [...$c, 'base_url' => null], 'KBIZ_BASE_URL is not set.'];
        yield 'blank base url' => [fn (array $c) => [...$c, 'base_url' => '  '], 'KBIZ_BASE_URL is not set.'];
        yield 'http base url' => [fn (array $c) => [...$c, 'base_url' => 'http://bank.test'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url with path' => [fn (array $c) => [...$c, 'base_url' => 'https://bank.test/x'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url with credentials' => [fn (array $c) => [...$c, 'base_url' => 'https://u:p@bank.test'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url other port' => [fn (array $c) => [...$c, 'base_url' => 'https://bank.test:8443'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url empty port' => [fn (array $c) => [...$c, 'base_url' => 'https://bank.test:'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url force query' => [fn (array $c) => [...$c, 'base_url' => 'https://bank.test?'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'base url fragment' => [fn (array $c) => [...$c, 'base_url' => 'https://bank.test#x'], 'KBIZ_BASE_URL must be an https origin'];
        yield 'timeout zero' => [fn (array $c) => [...$c, 'timeout_seconds' => '0'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout too long' => [fn (array $c) => [...$c, 'timeout_seconds' => '46'], 'KBIZ_TIMEOUT_SECONDS must be a whole number of seconds between 1 and 45.'];
        yield 'timeout of the old maximum' => [fn (array $c) => [...$c, 'timeout_seconds' => '120'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'integer timeout too long' => [fn (array $c) => [...$c, 'timeout_seconds' => 46], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout with unit' => [fn (array $c) => [...$c, 'timeout_seconds' => '20s'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout exponent' => [fn (array $c) => [...$c, 'timeout_seconds' => '1e1'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout decimal' => [fn (array $c) => [...$c, 'timeout_seconds' => '20.5'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout negative' => [fn (array $c) => [...$c, 'timeout_seconds' => '-5'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'timeout leading zero' => [fn (array $c) => [...$c, 'timeout_seconds' => '020'], 'KBIZ_TIMEOUT_SECONDS must be a whole number'];
        yield 'missing path' => [self::patchApi(3, 'path', null), 'KBIZ_API_3_PATH is not set.'];
        yield 'relative path' => [self::patchApi(3, 'path', 'p/three'), 'KBIZ_API_3_PATH must start with /.'];
        yield 'protocol-relative path' => [self::patchApi(3, 'path', '//evil.test/x'), 'KBIZ_API_3_PATH must not contain // or a scheme.'];
        yield 'double slash inside' => [self::patchApi(3, 'path', '/a//b'), 'KBIZ_API_3_PATH must not contain // or a scheme.'];
        yield 'scheme in query' => [self::patchApi(3, 'path', '/a?u=https://evil.test'), 'KBIZ_API_3_PATH must not contain // or a scheme.'];
        yield 'path traversal' => [self::patchApi(3, 'path', '/p/../x'), 'KBIZ_API_3_PATH must not contain . or .. segments.'];
        yield 'dot segment' => [self::patchApi(3, 'path', '/p/./x'), 'KBIZ_API_3_PATH must not contain . or .. segments.'];
        yield 'trailing dot dot' => [self::patchApi(3, 'path', '/p/..'), 'KBIZ_API_3_PATH must not contain . or .. segments.'];
        yield 'fragment' => [self::patchApi(3, 'path', '/p#x'), 'KBIZ_API_3_PATH must not contain # or backslash.'];
        yield 'backslash' => [self::patchApi(3, 'path', '/p\\x'), 'KBIZ_API_3_PATH must not contain # or backslash.'];
        yield 'space' => [self::patchApi(3, 'path', '/p x'), 'KBIZ_API_3_PATH must not contain whitespace or control characters.'];
        yield 'control character' => [self::patchApi(3, 'path', "/p\x7Fx"), 'KBIZ_API_3_PATH must not contain whitespace or control characters.'];
        // QA round 2: surrounding whitespace is an error (as in the worker), never trimmed away.
        yield 'trailing tab' => [self::patchApi(3, 'path', "/p\t"), 'KBIZ_API_3_PATH must not contain whitespace or control characters.'];
        yield 'trailing space' => [self::patchApi(3, 'path', '/p '), 'KBIZ_API_3_PATH must not contain whitespace or control characters.'];
        yield 'trailing newline' => [self::patchApi(3, 'path', "/p\n"), 'KBIZ_API_3_PATH must not contain whitespace or control characters.'];
        yield 'leading space' => [self::patchApi(3, 'path', ' /p'), 'KBIZ_API_3_PATH must start with /.'];
        yield 'whitespace only' => [self::patchApi(3, 'path', '   '), 'KBIZ_API_3_PATH must start with /.'];
        yield 'empty path' => [self::patchApi(3, 'path', ''), 'KBIZ_API_3_PATH is not set.'];
        yield 'bad escape' => [self::patchApi(3, 'path', '/p%ZZ'), 'KBIZ_API_3_PATH has an invalid percent escape.'];
        yield 'truncated escape' => [self::patchApi(3, 'path', '/p%4'), 'KBIZ_API_3_PATH has an invalid percent escape.'];
        yield 'too long' => [self::patchApi(3, 'path', '/'.str_repeat('a', 2048)), 'KBIZ_API_3_PATH must be at most 2048 bytes.'];
        yield 'approved equals rejected' => [self::patchApiJson(3, 'values', ['state_approved' => 'SAME', 'state_rejected' => 'SAME']), 'KBIZ_API_3_VALUES state_approved and state_rejected must be non-empty and different.'];
        yield 'approved empty' => [self::patchApiJson(3, 'values', ['state_approved' => '', 'state_rejected' => 'NO']), 'KBIZ_API_3_VALUES state_approved and state_rejected must be non-empty and different.'];
        yield 'handoff selector without group' => [self::patchSelector(5, '#k_handoff=[A-Za-z0-9%]+#'), 'KBIZ_SELECTOR_5 must contain a capture group'];
        yield 'handoff selector non-capturing only' => [self::patchSelector(5, '#k_handoff=(?:[A-Za-z0-9%]+)#'), 'KBIZ_SELECTOR_5 must contain a capture group'];
        yield 'headers not json' => [self::patchApi(1, 'headers', '{nope'), 'KBIZ_API_1_HEADERS must be a JSON object.'];
        yield 'headers json list' => [self::patchApi(1, 'headers', '["a"]'), 'KBIZ_API_1_HEADERS must be a JSON object.'];
        yield 'header with newline' => [self::patchApi(1, 'headers', '{"X-A":"a\r\nX-B: b"}'), 'KBIZ_API_1_HEADERS must map valid header names'];
        yield 'header bad name' => [self::patchApi(1, 'headers', '{"X A":"a"}'), 'KBIZ_API_1_HEADERS must map valid header names'];
        yield 'fields missing entirely' => [self::patchApi(6, 'fields', null), 'KBIZ_API_6_FIELDS is missing logical field "handoff_token".'];
        yield 'field missing' => [self::patchApi(2, 'fields', '{"login_name":"a"}'), 'KBIZ_API_2_FIELDS is missing logical field "login_secret".'];
        yield 'unknown field' => [self::patchApiJson(3, 'fields', ['approval_state' => 'a', 'typo' => 'b']), 'KBIZ_API_3_FIELDS has unknown logical field "typo".'];
        yield 'empty field value' => [self::patchApiJson(3, 'fields', ['approval_state' => '']), 'KBIZ_API_3_FIELDS value for "approval_state" must be a non-empty string.'];
        yield 'values missing' => [self::patchApi(3, 'values', null), 'KBIZ_API_3_VALUES is missing logical value "state_approved".'];
        yield 'unknown value' => [self::patchApiJson(3, 'values', ['state_approved' => 'a', 'state_rejected' => 'b', 'x' => 'c']), 'KBIZ_API_3_VALUES has unknown logical value "x".'];
        yield 'non-scalar value' => [self::patchApiJson(3, 'values', ['state_approved' => ['a'], 'state_rejected' => 'b']), 'KBIZ_API_3_VALUES value for "state_approved" must be a string or integer.'];
        yield 'missing selector' => [self::patchSelector(2, null), 'KBIZ_SELECTOR_2 is not set.'];
        yield 'invalid xpath' => [self::patchSelector(1, '//input[@name='), 'KBIZ_SELECTOR_1 must be a valid XPath expression.'];
        yield 'invalid regex' => [self::patchSelector(5, '#(unclosed#'), 'KBIZ_SELECTOR_5 must be a valid PCRE pattern including delimiters.'];
    }

    #[DataProvider('brokenConfigurations')]
    public function test_fails_fast_naming_the_variable(callable $mutate, string $expectedMessage): void
    {
        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessage($expectedMessage);

        KbizConfig::fromArray($mutate(FakeBank::config()));
    }

    public function test_error_messages_never_contain_the_value(): void
    {
        $secretLooking = 'https://SECRET-HOST.example/with/path';
        try {
            KbizConfig::fromArray([...FakeBank::config(), 'base_url' => $secretLooking]);
            $this->fail('expected exception');
        } catch (KbizConfigException $exception) {
            $this->assertStringNotContainsString('SECRET-HOST', $exception->getMessage());
        }
    }

    public function test_unknown_logical_names_are_rejected_at_use(): void
    {
        $step = KbizConfig::fromArray(FakeBank::config())->step('login_page');

        $this->expectException(KbizConfigException::class);
        $step->field('login_secret');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedPaths(): iterable
    {
        yield 'query string' => ['/p/x?a=1&b=two'];
        yield 'escape in query is the query parser\'s business' => ['/p/x?a=%ZZ'];
        yield 'encoded slash' => ['/p/a%2Fb'];
        yield 'dots inside a segment' => ['/p/a..b/c.d'];
        yield 'non-ascii (as the worker accepts)' => ['/p/ก'];
    }

    #[DataProvider('acceptedPaths')]
    public function test_paths_accepted_like_the_worker_loader(string $path): void
    {
        $this->assertSame($path, KbizConfig::fromArray(self::patchApi(3, 'path', $path)(FakeBank::config()))->step('approval_status')->path);
    }

    /**
     * @return iterable<string, array{mixed, int}>
     */
    public static function timeouts(): iterable
    {
        yield 'unset' => [null, 20];
        yield 'empty' => ['', 20];
        yield 'text' => ['45', 45];
        yield 'padded' => [' 45 ', 45];
        yield 'integer' => [7, 7];
        yield 'maximum' => ['45', 45];
    }

    #[DataProvider('timeouts')]
    public function test_timeout_is_a_whole_number_of_seconds(mixed $raw, int $expected): void
    {
        $this->assertSame($expected, KbizConfig::fromArray([...FakeBank::config(), 'timeout_seconds' => $raw])->timeoutSeconds);
    }

    public function test_base_url_accepts_an_explicit_443(): void
    {
        $config = KbizConfig::fromArray([...FakeBank::config(), 'base_url' => 'https://Bank.test:443/']);

        $this->assertSame('https://Bank.test', $config->baseUrl);
        $this->assertSame('bank.test', $config->host);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function capturingSelectors(): iterable
    {
        yield 'plain group' => ['#k_handoff=([A-Za-z0-9%]+)#'];
        yield 'named group' => ['#k_handoff=(?<token>[A-Za-z0-9%]+)#'];
        yield 'bracket delimiters' => ['{k_handoff=([A-Za-z0-9%]+)}i'];
        yield 'extended mode with trailing comment' => ['/k_handoff=([A-Za-z0-9%]+) # the token/x'];
    }

    #[DataProvider('capturingSelectors')]
    public function test_handoff_selector_with_a_capture_group_is_accepted(string $pattern): void
    {
        $this->assertSame($pattern, KbizConfig::fromArray(self::patchSelector(5, $pattern)(FakeBank::config()))->selector('handoff_token'));
    }

    private static function patchApi(int $n, string $key, mixed $value): callable
    {
        return function (array $config) use ($n, $key, $value) {
            $config['apis'][$n][$key] = $value;

            return $config;
        };
    }

    /**
     * @param  array<string, mixed>  $value
     */
    private static function patchApiJson(int $n, string $key, array $value): callable
    {
        return self::patchApi($n, $key, json_encode($value));
    }

    private static function patchSelector(int $n, ?string $value): callable
    {
        return function (array $config) use ($n, $value) {
            $config['selectors'][$n] = $value;

            return $config;
        };
    }
}
