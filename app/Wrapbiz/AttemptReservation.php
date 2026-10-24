<?php

namespace App\Wrapbiz;

use InvalidArgumentException;

/**
 * The answer of registration_code_begin_attempt(). Only a Reserved attempt
 * carries a reservation id; it never leaves the server and is handed back
 * to release exactly this attempt's slot.
 */
final readonly class AttemptReservation
{
    /** How long the database keeps an unsettled reservation (registration_code_begin_attempt). */
    public const int TTL_SECONDS = 180;

    private const string UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';

    private function __construct(
        public LoginAttempt $attempt,
        public ?string $reservationId,
    ) {}

    public static function reserved(string $reservationId): self
    {
        $id = strtolower($reservationId);
        if (preg_match(self::UUID_PATTERN, $id) !== 1) {
            throw new InvalidArgumentException('reservation id must be a UUID');
        }

        return new self(LoginAttempt::Reserved, $id);
    }

    public static function refused(LoginAttempt $attempt): self
    {
        if ($attempt === LoginAttempt::Reserved) {
            throw new InvalidArgumentException('a reserved attempt needs its reservation id');
        }

        return new self($attempt, null);
    }
}
