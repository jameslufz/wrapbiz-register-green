<?php

use App\Kbiz\KbizConfig;

/*
 * Raw KBIZ_* values. They are parsed and validated by App\Kbiz\KbizConfig,
 * which also documents which <n> belongs to which logical step.
 */

$apis = [];
foreach (array_keys(KbizConfig::STEPS) as $n) {
    $apis[$n] = [
        'path' => env("KBIZ_API_{$n}_PATH"),
        'headers' => env("KBIZ_API_{$n}_HEADERS"),
        'fields' => env("KBIZ_API_{$n}_FIELDS"),
        'values' => env("KBIZ_API_{$n}_VALUES"),
    ];
}

$selectors = [];
foreach (array_keys(KbizConfig::SELECTORS) as $n) {
    $selectors[$n] = env("KBIZ_SELECTOR_{$n}");
}

return [
    'base_url' => env('KBIZ_BASE_URL'),
    // Raw text on purpose: KbizConfig rejects anything but a whole number.
    'timeout_seconds' => env('KBIZ_TIMEOUT_SECONDS'),
    'apis' => $apis,
    'selectors' => $selectors,
];
