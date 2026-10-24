<?php

namespace Tests\Support;

use App\Security\DnsResolver;

final class FakeDnsResolver implements DnsResolver
{
    /**
     * @param  array<string, list<string>>  $records
     */
    public function __construct(private array $records) {}

    public function resolve(string $host): array
    {
        return $this->records[rtrim($host, '.')] ?? [];
    }
}
