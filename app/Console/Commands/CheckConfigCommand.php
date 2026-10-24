<?php

namespace App\Console\Commands;

use App\Kbiz\KbizConfig;
use App\Kbiz\KbizConfigException;
use App\Wrapbiz\DatabaseTlsPolicy;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;

/**
 * Validates every setting the site needs, naming each problem's variable
 * but never printing a value.
 */
final class CheckConfigCommand extends Command
{
    protected $signature = 'wrapbiz:check-config';

    protected $description = 'Validate bank, key and database configuration without printing any values';

    public function handle(): int
    {
        $problems = array_values(array_filter([
            $this->attempt(fn () => KbizConfig::fromArray((array) config('kbiz'))),
            $this->attempt(fn () => WrapbizSettings::fromArray((array) config('wrapbiz'))),
            $this->appKeyProblem(),
            $this->attempt(fn () => DatabaseTlsPolicy::assertSafe((array) config('database.connections.wrapbiz'))),
        ]));

        foreach ($problems as $problem) {
            $this->error($problem);
        }
        if ($problems !== []) {
            return self::FAILURE;
        }

        $this->info('KBIZ_*, WRAPBIZ_*, TRUSTED_PROXIES and APP_KEY configuration is complete.');

        return self::SUCCESS;
    }

    private function attempt(callable $check): ?string
    {
        try {
            $check();
        } catch (KbizConfigException $exception) {
            return $exception->getMessage();
        }

        return null;
    }

    private function appKeyProblem(): ?string
    {
        $key = config('app.key');
        if (! is_string($key) || $key === '') {
            return 'APP_KEY is not set (run `php artisan key:generate`).';
        }

        $raw = str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7), true) : $key;
        $cipher = (string) config('app.cipher');

        return is_string($raw) && Encrypter::supported($raw, $cipher)
            ? null
            : "APP_KEY is not a valid key for {$cipher} (run `php artisan key:generate`).";
    }
}
