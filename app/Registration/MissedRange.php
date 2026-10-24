<?php

namespace App\Registration;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use InvalidArgumentException;

/**
 * Transactions a reattached account will never deliver: the worker's
 * catch-up only goes back a fixed number of calendar days (Asia/Bangkok,
 * the audited catch-up limit register_connection returns), so anything
 * after the point it polls from and before that window is lost.
 *
 * The oldest day the worker still fetches is its reach day, one day past
 * the limit: today - N - 1 (wrapbiz core.ReachDay; the nightly sweep makes
 * the margin fetch of that day). The worker reports the days before it as
 * missed (catchup.missed ends at today - N - 2), and so does this range.
 */
final readonly class MissedRange
{
    public const string TIMEZONE = 'Asia/Bangkok';

    private function __construct(
        public CarbonImmutable $from,
        public CarbonImmutable $lastMissedDay,
    ) {}

    /**
     * @param  ?DateTimeInterface  $pollingStart  the account's last successful poll, or its registration time when it was never polled
     */
    public static function between(?DateTimeInterface $pollingStart, DateTimeInterface $now, int $catchUpDays): ?self
    {
        if ($catchUpDays < 1) {
            throw new InvalidArgumentException('catch-up days must be positive');
        }
        if ($pollingStart === null) {
            return null;
        }

        $from = CarbonImmutable::instance($pollingStart)->setTimezone(self::TIMEZONE);
        $reachDay = CarbonImmutable::instance($now)->setTimezone(self::TIMEZONE)->startOfDay()->subDays($catchUpDays + 1);
        if ($from->startOfDay()->greaterThanOrEqualTo($reachDay)) {
            return null;
        }

        return new self($from, $reachDay->subDay());
    }
}
