<?php

namespace App\Registration;

use Carbon\CarbonImmutable;

final readonly class RegistrationResult
{
    /**
     * @param  ?string  $maskedNumber  null when the database result could not be matched to a selected account
     * @param  ?int  $catchUpDays  the worker's catch-up window in days (the audited limit its claims use); null when the database has none or it could not be read
     * @param  ?MissedRange  $missed  transactions of a reattached account that are older than the worker's catch-up window
     * @param  bool  $handover  a different K BIZ user took over a released account: fresh start on a new endpoint, no catch-up
     * @param  ?HandoverGap  $handoverGap  transactions of a hand-over that may not have been delivered; null when the range is empty or unreadable
     * @param  bool  $missedUnknown  a reattached account whose missed range cannot be told, because the catch-up window is unknown: the page warns instead
     * @param  ?CarbonImmutable  $disconnectedSince  with $missedUnknown: where the worker's fetch starts (Bangkok time), when known
     */
    public function __construct(
        public string $accountId,
        public ?string $maskedNumber,
        public bool $reattached,
        public ?int $catchUpDays = null,
        public ?MissedRange $missed = null,
        public bool $handover = false,
        public ?HandoverGap $handoverGap = null,
        public bool $missedUnknown = false,
        public ?CarbonImmutable $disconnectedSince = null,
    ) {}
}
