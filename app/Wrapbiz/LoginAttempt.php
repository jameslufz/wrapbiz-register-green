<?php

namespace App\Wrapbiz;

/**
 * Text returned by registration_code_begin_attempt(). Only Reserved allows
 * a bank login; it holds one of the code's five attempt slots until it is
 * settled by endLoginAttempt() or recordFailedLogin().
 */
enum LoginAttempt: string
{
    case Reserved = 'ok';
    case Busy = 'busy';
    case Unknown = 'unknown';
    case Used = 'used';
    case Expired = 'expired';
    case Locked = 'locked';
    case Exhausted = 'exhausted';

    private const string MSG_BUSY = 'มีการเข้าสู่ระบบด้วยรหัสนี้ค้างอยู่ กรุณารอสักครู่แล้วลองใหม่';

    /**
     * The code state behind a refusal; null for Reserved and Busy, where the
     * code itself is still usable.
     */
    public function codeStatus(): ?CodeStatus
    {
        return match ($this) {
            self::Reserved, self::Busy => null,
            self::Unknown => CodeStatus::Unknown,
            self::Used => CodeStatus::Used,
            self::Expired => CodeStatus::Expired,
            self::Locked => CodeStatus::Locked,
            self::Exhausted => CodeStatus::Exhausted,
        };
    }

    public function message(): string
    {
        return match ($this) {
            self::Reserved => '',
            self::Busy => self::MSG_BUSY,
            default => $this->codeStatus()?->message() ?? '',
        };
    }
}
