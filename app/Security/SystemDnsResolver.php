<?php

namespace App\Security;

final class SystemDnsResolver implements DnsResolver
{
    public function resolve(string $host): array
    {
        $addresses = [];
        foreach ([[DNS_A, 'ip'], [DNS_AAAA, 'ipv6']] as [$type, $key]) {
            $records = @dns_get_record($host, $type);
            foreach (is_array($records) ? $records : [] as $record) {
                if (isset($record[$key]) && is_string($record[$key])) {
                    $addresses[] = $record[$key];
                }
            }
        }

        return array_values(array_unique($addresses));
    }
}
