<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * The snippets shown to customers must actually verify real signatures.
 */
final class VerificationSnippetTest extends TestCase
{
    private const string BODY = '{"id":"evt_1","type":"transaction.created","data":{"amount":"1500.00","memo":"ไทย"}}';

    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__, 2).'/resources/snippets/wrapbiz-verify.php';
    }

    /**
     * @return array{0: string, 1: string} [secret key, base64 public key]
     */
    private static function keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [sodium_crypto_sign_secretkey($pair), base64_encode(sodium_crypto_sign_publickey($pair))];
    }

    private static function sign(string $secretKey, string $id, string $timestamp, string $body): string
    {
        return 'v1a,'.base64_encode(sodium_crypto_sign_detached("{$id}.{$timestamp}.{$body}", $secretKey));
    }

    /**
     * @return array<string, string>
     */
    private static function headers(string $signature, ?string $timestamp = null): array
    {
        return ['webhook-id' => 'evt_1', 'webhook-timestamp' => $timestamp ?? (string) time(), 'webhook-signature' => $signature];
    }

    public function test_php_snippet_accepts_a_valid_signature(): void
    {
        [$secret, $public] = self::keypair();
        $ts = (string) time();

        $this->assertTrue(wrapbiz_verify_webhook(self::BODY, self::headers(self::sign($secret, 'evt_1', $ts, self::BODY), $ts), [$public]));
    }

    public function test_php_snippet_accepts_any_of_multiple_signatures_and_keys(): void
    {
        [$oldSecret] = self::keypair();
        [$newSecret, $newPublic] = self::keypair();
        [, $unrelatedPublic] = self::keypair();
        $ts = (string) time();
        $header = self::sign($oldSecret, 'evt_1', $ts, self::BODY).' '.self::sign($newSecret, 'evt_1', $ts, self::BODY);

        $this->assertTrue(wrapbiz_verify_webhook(self::BODY, self::headers($header, $ts), [$unrelatedPublic, $newPublic]));
    }

    public function test_php_snippet_rejects_tampering_wrong_key_and_stale_timestamps(): void
    {
        [$secret, $public] = self::keypair();
        [, $otherPublic] = self::keypair();
        $ts = (string) time();
        $signature = self::sign($secret, 'evt_1', $ts, self::BODY);

        $this->assertFalse(wrapbiz_verify_webhook(self::BODY.' ', self::headers($signature, $ts), [$public]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, self::headers($signature, $ts), [$otherPublic]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, ['webhook-id' => 'evt_2'] + self::headers($signature, $ts), [$public]));

        $old = (string) (time() - 600);
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, self::headers(self::sign($secret, 'evt_1', $old, self::BODY), $old), [$public]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, self::headers('v1,'.substr($signature, 4), $ts), [$public]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, self::headers('v1a,not-base64!', $ts), [$public]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, self::headers($signature, 'abc'), [$public]));
        $this->assertFalse(wrapbiz_verify_webhook(self::BODY, [], [$public]));
    }

    public function test_node_snippet_verifies_the_same_signatures(): void
    {
        $node = (new ExecutableFinder)->find('node');
        if ($node === null) {
            $this->markTestSkipped('node is not installed');
        }

        [$secret, $public] = self::keypair();
        [, $otherPublic] = self::keypair();
        $ts = (string) time();
        $signature = self::sign($secret, 'evt_1', $ts, self::BODY);
        $cases = [
            'valid' => [self::BODY, self::headers('v1a,'.str_repeat('A', 86).'== '.$signature, $ts), [$public]],
            'tampered' => [self::BODY.'x', self::headers($signature, $ts), [$public]],
            'wrong key' => [self::BODY, self::headers($signature, $ts), [$otherPublic]],
            'stale' => [self::BODY, self::headers($signature, (string) (time() - 600)), [$public]],
        ];

        $script = 'import { verifyWrapbizWebhook } from '.json_encode('file://'.dirname(__DIR__, 2).'/resources/snippets/wrapbiz-verify.mjs').';'
            .'const cases = JSON.parse(process.argv[1]);'
            .'const out = {}; for (const [name, [body, headers, keys]] of Object.entries(cases)) out[name] = verifyWrapbizWebhook(Buffer.from(body, "utf8"), headers, keys);'
            .'console.log(JSON.stringify(out));';

        $process = new Process([$node, '--input-type=module', '-e', $script, json_encode($cases, JSON_UNESCAPED_UNICODE)]);
        $process->mustRun();

        $this->assertSame(
            ['valid' => true, 'tampered' => false, 'wrong key' => false, 'stale' => false],
            json_decode($process->getOutput(), true),
        );
    }

    public function test_php_handler_applies_each_webhook_id_once_and_answers_redeliveries_with_200(): void
    {
        [$secret, $public] = self::keypair();
        $ts = (string) time();
        $headers = self::headers(self::sign($secret, 'evt_1', $ts, self::BODY), $ts);
        $seen = [];
        $credits = [];
        $applyOnce = function (string $webhookId, array $event) use (&$seen, &$credits) {
            if (isset($seen[$webhookId])) {
                return;
            }
            $seen[$webhookId] = true;
            $credits[] = $event['data']['amount'];
        };

        $this->assertSame(200, wrapbiz_handle_webhook(self::BODY, $headers, [$public], $applyOnce));
        $this->assertSame(200, wrapbiz_handle_webhook(self::BODY, $headers, [$public], $applyOnce));

        $this->assertSame(['1500.00'], $credits);
    }

    public function test_php_handler_refuses_bad_signatures_stale_timestamps_and_non_json(): void
    {
        [$secret, $public] = self::keypair();
        $ts = (string) time();
        $old = (string) (time() - 301);
        $never = function () {
            $this->fail('must not be applied');
        };

        $this->assertSame(401, wrapbiz_handle_webhook(self::BODY.' ', self::headers(self::sign($secret, 'evt_1', $ts, self::BODY), $ts), [$public], $never));
        $this->assertSame(401, wrapbiz_handle_webhook(self::BODY, self::headers(self::sign($secret, 'evt_1', $old, self::BODY), $old), [$public], $never));
        $this->assertSame(400, wrapbiz_handle_webhook('not json', self::headers(self::sign($secret, 'evt_1', $ts, 'not json'), $ts), [$public], $never));
    }

    public function test_node_handler_applies_each_webhook_id_once(): void
    {
        $node = (new ExecutableFinder)->find('node');
        if ($node === null) {
            $this->markTestSkipped('node is not installed');
        }

        [$secret, $public] = self::keypair();
        $ts = (string) time();
        $old = (string) (time() - 301);
        $cases = [
            'first' => [self::BODY, self::headers(self::sign($secret, 'evt_1', $ts, self::BODY), $ts)],
            'redelivery' => [self::BODY, self::headers(self::sign($secret, 'evt_1', $ts, self::BODY), $ts)],
            'stale' => [self::BODY, self::headers(self::sign($secret, 'evt_1', $old, self::BODY), $old)],
            'not json' => ['nope', self::headers(self::sign($secret, 'evt_1', $ts, 'nope'), $ts)],
        ];

        $script = 'import { handleWrapbizWebhook } from '.json_encode('file://'.dirname(__DIR__, 2).'/resources/snippets/wrapbiz-verify.mjs').';'
            .'const [cases, key] = JSON.parse(process.argv[1]); const seen = new Set(); const applied = [];'
            .'const applyOnce = async (id, event) => { if (seen.has(id)) return; seen.add(id); applied.push(event.data.amount); };'
            .'const out = {}; for (const [name, [body, headers]] of Object.entries(cases)) out[name] = await handleWrapbizWebhook(Buffer.from(body, "utf8"), headers, [key], applyOnce);'
            .'console.log(JSON.stringify({ out, applied }));';

        $process = new Process([$node, '--input-type=module', '-e', $script, json_encode([$cases, $public], JSON_UNESCAPED_UNICODE)]);
        $process->mustRun();

        $this->assertSame(
            ['out' => ['first' => 200, 'redelivery' => 200, 'stale' => 401, 'not json' => 400], 'applied' => ['1500.00']],
            json_decode($process->getOutput(), true),
        );
    }
}
