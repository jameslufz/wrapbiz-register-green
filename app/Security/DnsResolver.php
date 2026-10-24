<?php

namespace App\Security;

interface DnsResolver
{
    /**
     * @return list<string> every A and AAAA address for the host; empty if it does not resolve
     */
    public function resolve(string $host): array;
}
