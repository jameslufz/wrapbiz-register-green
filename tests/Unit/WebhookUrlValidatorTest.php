<?php

namespace Tests\Unit;

use App\Security\IpBlocklist;
use App\Security\WebhookUrlProblem;
use App\Security\WebhookUrlValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FakeDnsResolver;

final class WebhookUrlValidatorTest extends TestCase
{
    private function validator(): WebhookUrlValidator
    {
        return new WebhookUrlValidator(new FakeDnsResolver([
            'hooks.example.com' => ['93.184.216.34'],
            'v6.example.com' => ['2606:4700::1111'],
            'mixed.example.com' => ['93.184.216.34', '10.0.0.5'],
            'internal.example.com' => ['192.168.1.10'],
            'mapped.example.com' => ['::ffff:127.0.0.1'],
            'nat64.example.com' => ['64:ff9b::a00:1'],
            'sixtofour.example.com' => ['2002:c0a8:0101::1'],
            'metadata.example.com' => ['169.254.169.254'],
            'ula.example.com' => ['fd00::1'],
        ]));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedUrls(): iterable
    {
        yield 'plain' => ['https://hooks.example.com/wrapbiz'];
        yield 'explicit 443' => ['https://hooks.example.com:443/wrapbiz?x=1'];
        yield 'ipv6 only host' => ['https://v6.example.com/'];
        yield 'public ipv4 literal' => ['https://93.184.216.34/hook'];
        yield 'public ipv6 literal' => ['https://[2606:4700::1111]/hook'];
        yield 'uppercase host' => ['https://HOOKS.example.com/x'];
        yield 'trailing dot' => ['https://hooks.example.com./x'];
        yield 'percent-encoded path' => ['https://hooks.example.com/%E0%B8%81'];
        // Accepted by Go's url.Parse as well (checked with go1.27 over the QA URL list).
        yield 'no path, query only' => ['https://hooks.example.com?x'];
        yield 'no path' => ['https://hooks.example.com'];
        yield 'ipv6 literal with 443' => ['https://[2606:4700::1111]:443/a'];
        yield 'sub-delims in path' => ["https://hooks.example.com/~a!$&'()*+,;=:@"];
        yield 'characters Go leaves unescaped' => ['https://hooks.example.com/a"b<c>{d}|^`'];
        yield 'encoded slash' => ['https://hooks.example.com/a%2Fb'];
        yield 'encoded space in query' => ['https://hooks.example.com/?a=1&b=%20'];
    }

    #[DataProvider('acceptedUrls')]
    public function test_accepts_public_https_urls(string $url): void
    {
        $this->assertNull($this->validator()->validate($url));
    }

    /**
     * @return iterable<string, array{string, WebhookUrlProblem}>
     */
    public static function rejectedUrls(): iterable
    {
        yield 'empty' => ['', WebhookUrlProblem::Malformed];
        yield 'http' => ['http://hooks.example.com/x', WebhookUrlProblem::NotHttps];
        yield 'uppercase scheme' => ['HTTPS://hooks.example.com/x', WebhookUrlProblem::NotHttps];
        yield 'ftp' => ['ftp://hooks.example.com/x', WebhookUrlProblem::NotHttps];
        yield 'javascript' => ['javascript:alert(1)', WebhookUrlProblem::NotHttps];
        yield 'whitespace' => ['https://hooks.example.com/a b', WebhookUrlProblem::Malformed];
        yield 'unicode path' => ['https://hooks.example.com/ก', WebhookUrlProblem::Malformed];
        yield 'newline' => ["https://hooks.example.com/\n", WebhookUrlProblem::Malformed];
        yield 'too long' => ['https://hooks.example.com/'.str_repeat('a', 2048), WebhookUrlProblem::TooLong];
        yield 'userinfo' => ['https://user:pass@hooks.example.com/x', WebhookUrlProblem::HasCredentials];
        yield 'user only' => ['https://user@hooks.example.com/x', WebhookUrlProblem::HasCredentials];
        yield 'fragment' => ['https://hooks.example.com/x#y', WebhookUrlProblem::HasFragment];
        yield 'port 8443' => ['https://hooks.example.com:8443/x', WebhookUrlProblem::WrongPort];
        yield 'port 80' => ['https://hooks.example.com:80/x', WebhookUrlProblem::WrongPort];
        yield 'no host' => ['https:///x', WebhookUrlProblem::Malformed];
        yield 'single label' => ['https://localhost/x', WebhookUrlProblem::InvalidHost];
        yield 'decimal ip' => ['https://2130706433/x', WebhookUrlProblem::InvalidHost];
        yield 'short ip' => ['https://127.1/x', WebhookUrlProblem::InvalidHost];
        yield 'hex ip' => ['https://0x7f.0.0.1/x', WebhookUrlProblem::InvalidHost];
        yield 'underscore host' => ['https://bad_host.example.com/x', WebhookUrlProblem::InvalidHost];
        yield 'unresolvable' => ['https://nothing.example.com/x', WebhookUrlProblem::DoesNotResolve];
        yield 'private dns' => ['https://internal.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'one private record' => ['https://mixed.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'mapped dns' => ['https://mapped.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'nat64 dns' => ['https://nat64.example.com/x', WebhookUrlProblem::NotPublic];
        yield '6to4 dns' => ['https://sixtofour.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'metadata dns' => ['https://metadata.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'ula dns' => ['https://ula.example.com/x', WebhookUrlProblem::NotPublic];
        yield 'loopback literal' => ['https://127.0.0.1/x', WebhookUrlProblem::NotPublic];
        yield 'metadata literal' => ['https://169.254.169.254/latest', WebhookUrlProblem::NotPublic];
        yield 'ipv6 loopback literal' => ['https://[::1]/x', WebhookUrlProblem::NotPublic];
        yield 'ipv6 mapped literal' => ['https://[::ffff:10.0.0.1]/x', WebhookUrlProblem::NotPublic];
        yield 'ipv6 mapped hex literal' => ['https://[::ffff:7f00:1]/x', WebhookUrlProblem::NotPublic];
        yield 'ipv6 garbage literal' => ['https://[not-an-ip]/x', WebhookUrlProblem::InvalidHost];
        // Rejected by Go's url.Parse (go1.27), so the worker could never deliver to them.
        yield 'go: bad escape in path' => ['https://hooks.example.com/%ZZ', WebhookUrlProblem::Malformed];
        yield 'go: lone percent' => ['https://hooks.example.com/%', WebhookUrlProblem::Malformed];
        yield 'go: truncated escape' => ['https://hooks.example.com/%4', WebhookUrlProblem::Malformed];
        yield 'go: double port' => ['https://hooks.example.com:443:443/a', WebhookUrlProblem::WrongPort];
        yield 'go: escape in host' => ['https://h%41oks.example.com/', WebhookUrlProblem::InvalidHost];
        yield 'go: backslash userinfo' => ['https://hooks.example.com\\@evil.com/', WebhookUrlProblem::Malformed];
        yield 'go: tab' => ["https://hooks.example.com/a\tb", WebhookUrlProblem::Malformed];
        yield 'go: missing bracket' => ['https://[2606:4700::1111/a', WebhookUrlProblem::Malformed];
        // Accepted by Go but refused here on purpose (stricter is safe).
        yield 'bad escape in query' => ['https://hooks.example.com/a?x=%ZZ', WebhookUrlProblem::Malformed];
        yield 'lone percent in query' => ['https://hooks.example.com/?q=%', WebhookUrlProblem::Malformed];
        yield 'encoded NUL' => ['https://hooks.example.com/%00', WebhookUrlProblem::Malformed];
        yield 'encoded CRLF' => ['https://hooks.example.com/a%0d%0aX-Injected:1', WebhookUrlProblem::Malformed];
        yield 'encoded DEL' => ['https://hooks.example.com/%7f', WebhookUrlProblem::Malformed];
        yield 'backslash in path' => ['https://hooks.example.com/a\\b', WebhookUrlProblem::Malformed];
        yield 'port with leading zero' => ['https://hooks.example.com:0443/a', WebhookUrlProblem::WrongPort];
        yield 'empty port' => ['https://hooks.example.com:/a', WebhookUrlProblem::WrongPort];
        yield 'port out of range' => ['https://hooks.example.com:65536/a', WebhookUrlProblem::WrongPort];
        yield 'ipv6 literal other port' => ['https://[2606:4700::1111]:8443/a', WebhookUrlProblem::WrongPort];
        yield 'ipv6 literal junk after bracket' => ['https://[2606:4700::1111]x/a', WebhookUrlProblem::Malformed];
        yield 'ipv6 zone id' => ['https://[2606:4700::1111%25eth0]/a', WebhookUrlProblem::InvalidHost];
        yield 'underscore host (Go accepts, DNS does not)' => ['https://exa_mple.com/a', WebhookUrlProblem::InvalidHost];
        yield 'idn not punycoded' => ['https://ตัวอย่าง.com/a', WebhookUrlProblem::Malformed];
        yield 'empty host with port' => ['https://:443/a', WebhookUrlProblem::Malformed];
    }

    #[DataProvider('rejectedUrls')]
    public function test_rejects_unsafe_urls(string $url, WebhookUrlProblem $expected): void
    {
        $this->assertSame($expected, $this->validator()->validate($url));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function addresses(): iterable
    {
        foreach ([
            '0.0.0.0', '0.1.2.3', '10.1.2.3', '100.64.0.1', '100.127.255.255', '127.0.0.1', '169.254.169.254',
            '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.1', '192.88.99.1', '192.168.0.1', '198.18.0.1',
            '198.51.100.1', '203.0.113.1', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
            '::', '::1', '::ffff:8.8.8.8', '::ffff:127.0.0.1', '::127.0.0.1', '64:ff9b::808:808', '64:ff9b:1::1',
            '100::1', '2001::1', '2001:db8::1', '2002:808:808::1', '3fff::1', 'fc00::1', 'fd12:3456::1',
            'fe80::1', 'fec0::1', 'ff02::1', 'not-an-ip', '',
        ] as $ip) {
            yield "blocked {$ip}" => [$ip, false];
        }
        foreach (['8.8.8.8', '1.1.1.1', '100.63.255.255', '100.128.0.1', '172.15.255.255', '172.32.0.1', '93.184.216.34', '2606:4700::1111', '2a00:1450::1', '2001:4860:4860::8888'] as $ip) {
            yield "public {$ip}" => [$ip, true];
        }
    }

    #[DataProvider('addresses')]
    public function test_blocklist(string $ip, bool $public): void
    {
        $this->assertSame($public, IpBlocklist::isPublic($ip));
    }

    public function test_wrong_port_message_tells_the_customer_what_to_do(): void
    {
        $message = WebhookUrlProblem::WrongPort->message();

        $this->assertStringContainsString('443', $message);
        $this->assertStringContainsString(':443', $message);
        $this->assertStringContainsString('ลบ', $message);
    }

    public function test_every_problem_has_a_thai_message(): void
    {
        foreach (WebhookUrlProblem::cases() as $problem) {
            $this->assertMatchesRegularExpression('/\p{Thai}/u', $problem->message());
        }
    }
}
