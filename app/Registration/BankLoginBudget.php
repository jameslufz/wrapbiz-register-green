<?php

namespace App\Registration;

use App\Wrapbiz\WrapbizSettings;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;

/**
 * Site-wide cap on credential submissions to the bank, so rotating client
 * addresses cannot turn this site into a password-guessing proxy. Only
 * consumed right before a real bank login, never by rejected requests.
 *
 * Check and consume happen under one cache lock: the counters' increment is
 * a plain read-modify-write on some stores (e.g. file), so parallel requests
 * could otherwise all pass the check.
 */
final readonly class BankLoginBudget
{
    private const string MINUTE_KEY = 'bank-login-global:minute';

    private const string HOUR_KEY = 'bank-login-global:hour';

    private const string LOCK_NAME = 'bank-login-global:lock';

    /** Upper bound on how long the lock is held if a process dies inside it. */
    private const int LOCK_TTL_SECONDS = 5;

    public const int LOCK_WAIT_SECONDS = 2;

    private const int LOCK_RETRY_MS = 10;

    public function __construct(
        private RateLimiter $limiter,
        private LockProvider $locks,
        private WrapbizSettings $settings,
    ) {}

    public function tryConsume(): bool
    {
        try {
            return $this->locks->lock(self::LOCK_NAME, self::LOCK_TTL_SECONDS)
                ->betweenBlockedAttemptsSleepFor(self::LOCK_RETRY_MS)
                ->block(self::LOCK_WAIT_SECONDS, fn () => $this->consumeWhileLocked());
        } catch (LockTimeoutException) {
            return false;
        }
    }

    private function consumeWhileLocked(): bool
    {
        if ($this->limiter->tooManyAttempts(self::MINUTE_KEY, $this->settings->bankLoginsPerMinute)
            || $this->limiter->tooManyAttempts(self::HOUR_KEY, $this->settings->bankLoginsPerHour)
        ) {
            return false;
        }

        $this->limiter->hit(self::MINUTE_KEY, 60);
        $this->limiter->hit(self::HOUR_KEY, 3600);

        return true;
    }
}
