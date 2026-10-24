<?php

namespace App\Wrapbiz;

use DateTimeImmutable;

final readonly class RegisteredAccount
{
    /**
     * @param  bool  $reattached  true when an expired account of the same K BIZ user was reconnected under its existing id
     * @param  ?DateTimeImmutable  $lastSuccessAt  the kept polling watermark of a reattached account; null when it was never polled or is new
     * @param  ?DateTimeImmutable  $registeredAt  when a reattached account was first registered; null for a new account
     * @param  ?int  $catchUpDays  the worker's catch-up window (POLL_CATCHUP_MAX_DAYS, fixed in the database); null when it could not be read
     * @param  bool  $handover  a different K BIZ user took over a released account: it starts fresh, like a new account, on a new endpoint
     * @param  ?DateTimeImmutable  $gapFrom  start of the hand-over range that may not have been delivered; null when there is none (or it is empty)
     * @param  ?DateTimeImmutable  $gapTo  end (exclusive) of that range; set exactly when $gapFrom is
     * @param  ?int  $gapDeliveredCount  how many transactions in that range were already delivered successfully; null when unknown
     * @param  ?int  $gapPendingCount  how many in that range are still queued or failed (pending, delivering or dead); null when unknown
     */
    public function __construct(
        public string $id,
        public bool $reattached,
        public ?DateTimeImmutable $lastSuccessAt = null,
        public ?DateTimeImmutable $registeredAt = null,
        public ?int $catchUpDays = null,
        public bool $handover = false,
        public ?DateTimeImmutable $gapFrom = null,
        public ?DateTimeImmutable $gapTo = null,
        public ?int $gapDeliveredCount = null,
        public ?int $gapPendingCount = null,
    ) {}

    /**
     * Where the worker's fetch window starts for a reattached account: its
     * watermark, or its registration time when it was never polled.
     */
    public function pollingStart(): ?DateTimeImmutable
    {
        return $this->reattached ? $this->lastSuccessAt ?? $this->registeredAt : null;
    }
}
