<?php

/*
 * One competing web worker for BankLoginBudgetTest: waits for the start
 * signal, then tries to take one bank login from the shared file cache and
 * prints 1 (granted) or 0.
 */

use App\Registration\BankLoginBudget;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\Repository;
use Illuminate\Filesystem\Filesystem;

require __DIR__.'/../../vendor/autoload.php';

[, $cacheDirectory, $startSignal, $perMinute] = $argv;

$store = new FileStore(new Filesystem, $cacheDirectory);
$settings = WrapbizSettings::fromArray([
    'seal_public_key' => base64_encode(str_repeat('s', 32)),
    'fingerprint_key' => base64_encode(str_repeat('f', 32)),
    'ip_hash_key' => base64_encode(str_repeat('i', 32)),
    'signing_public_keys' => 'k1:'.base64_encode(str_repeat('k', 32)),
    'bank_logins_per_minute' => $perMinute,
]);
$budget = new BankLoginBudget(new RateLimiter(new Repository($store)), $store, $settings);

$deadline = microtime(true) + 10;
while (! is_file($startSignal) && microtime(true) < $deadline) {
    usleep(1000);
}

echo $budget->tryConsume() ? '1' : '0';
