<?php

namespace App\Security;

/**
 * Point-in-time check of a customer webhook URL. The worker re-checks every
 * resolved address at dial time, so this is about early, clear feedback.
 */
final readonly class WebhookUrlValidator
{
    public const int MAX_LENGTH = 2048;

    private const string SCHEME = 'https://';

    public function __construct(private DnsResolver $resolver) {}

    public function validate(string $url): ?WebhookUrlProblem
    {
        if (strlen($url) > self::MAX_LENGTH) {
            return WebhookUrlProblem::TooLong;
        }
        if ($url === '' || preg_match('/^[\x21-\x7E]+$/D', $url) !== 1) {
            return WebhookUrlProblem::Malformed;
        }
        if (! str_starts_with($url, self::SCHEME)) {
            return WebhookUrlProblem::NotHttps;
        }
        if (str_contains($url, '#')) {
            return WebhookUrlProblem::HasFragment;
        }
        if (str_contains($url, '\\') || ! self::hasValidPercentEscapes($url)) {
            return WebhookUrlProblem::Malformed;
        }

        $rest = substr($url, strlen(self::SCHEME));
        $authority = substr($rest, 0, strcspn($rest, '/?'));
        if (str_contains($authority, '@')) {
            return WebhookUrlProblem::HasCredentials;
        }

        $hostAndPort = self::splitHostAndPort($authority);
        if ($hostAndPort === null) {
            return WebhookUrlProblem::Malformed;
        }
        [$host, $port] = $hostAndPort;
        if ($host === '') {
            return WebhookUrlProblem::Malformed;
        }
        if ($port !== null && $port !== '443') {
            return WebhookUrlProblem::WrongPort;
        }

        return $this->validateHost(strtolower($host));
    }

    /**
     * Every "%" must start a two-digit hex escape (Go's url.Parse rejects the
     * rest), and escapes may not smuggle control characters.
     */
    private static function hasValidPercentEscapes(string $url): bool
    {
        $offset = 0;
        while (($position = strpos($url, '%', $offset)) !== false) {
            $hex = substr($url, $position + 1, 2);
            if (strlen($hex) !== 2 || ! ctype_xdigit($hex)) {
                return false;
            }
            $byte = hexdec($hex);
            if ($byte < 0x20 || $byte === 0x7F) {
                return false;
            }
            $offset = $position + 3;
        }

        return true;
    }

    /**
     * @return array{0: string, 1: ?string}|null host (IPv6 literals keep their brackets) and the port text after ":", if any
     */
    private static function splitHostAndPort(string $authority): ?array
    {
        if (str_starts_with($authority, '[')) {
            $close = strpos($authority, ']');
            if ($close === false) {
                return null;
            }
            $after = substr($authority, $close + 1);
            if ($after !== '' && ! str_starts_with($after, ':')) {
                return null;
            }

            return [substr($authority, 0, $close + 1), $after === '' ? null : substr($after, 1)];
        }

        $colon = strpos($authority, ':');

        return $colon === false
            ? [$authority, null]
            : [substr($authority, 0, $colon), substr($authority, $colon + 1)];
    }

    private function validateHost(string $host): ?WebhookUrlProblem
    {
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $literal = substr($host, 1, -1);

            return filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false
                ? WebhookUrlProblem::InvalidHost
                : (IpBlocklist::isPublic($literal) ? null : WebhookUrlProblem::NotPublic);
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return IpBlocklist::isPublic($host) ? null : WebhookUrlProblem::NotPublic;
        }

        if (! self::isDnsHostname($host)) {
            return WebhookUrlProblem::InvalidHost;
        }

        $addresses = $this->resolver->resolve($host);
        if ($addresses === []) {
            return WebhookUrlProblem::DoesNotResolve;
        }
        foreach ($addresses as $address) {
            if (! IpBlocklist::isPublic($address)) {
                return WebhookUrlProblem::NotPublic;
            }
        }

        return null;
    }

    /**
     * RFC 1123 labels, at least two of them, and a top-level label that is
     * not purely numeric, so shorthand IPv4 forms like "2130706433" or
     * "127.1" are never treated as names.
     */
    private static function isDnsHostname(string $host): bool
    {
        $host = rtrim($host, '.');
        if ($host === '' || strlen($host) > 253) {
            return false;
        }

        $labels = explode('.', $host);
        if (count($labels) < 2) {
            return false;
        }
        foreach ($labels as $label) {
            if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label) !== 1) {
                return false;
            }
        }

        return preg_match('/[a-z]/', end($labels)) === 1;
    }
}
