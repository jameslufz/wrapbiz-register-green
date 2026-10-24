<?php

namespace App\Registration;

use Carbon\CarbonImmutable;
use DateTimeInterface;

/**
 * Transactions that may not have been delivered because a different K BIZ
 * user took over a released account: the account starts fresh, so the
 * customer checks this range against the bank statement. Some of them may
 * already have been delivered successfully (shown so they are not booked
 * twice), others may still be queued or have failed (shown so the customer
 * asks the operator). Shown in Asia/Bangkok time.
 */
final readonly class HandoverGap
{
    private function __construct(
        public CarbonImmutable $from,
        public CarbonImmutable $to,
        public ?int $deliveredCount,
        public ?int $pendingCount,
    ) {}

    /**
     * @param  ?int  $deliveredCount  transactions in the range delivered successfully; null when unknown
     * @param  ?int  $pendingCount  transactions in the range still queued or failed; null when unknown
     */
    public static function between(DateTimeInterface $from, DateTimeInterface $to, ?int $deliveredCount, ?int $pendingCount): self
    {
        return new self(
            CarbonImmutable::instance($from)->setTimezone(MissedRange::TIMEZONE),
            CarbonImmutable::instance($to)->setTimezone(MissedRange::TIMEZONE),
            $deliveredCount,
            $pendingCount,
        );
    }
}
