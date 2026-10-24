<?php

namespace App\Wrapbiz;

/**
 * What registration_account_states() says register_connection() would do
 * with a listed account. Only new and reattachable accounts may be selected;
 * register_connection() still refuses the others as the last line. A K BIZ
 * user is bound to one bank account for good: once it has one, every other
 * account it lists is UserBound.
 */
enum AccountState: string
{
    case New = 'new';
    case Reattachable = 'reattachable';
    case Held = 'held';
    case Registered = 'registered';
    case UserBound = 'user_bound';

    public const string MSG_USER_BOUND = 'ผู้ใช้ KBiz นี้ลงทะเบียนบัญชีอื่นไว้แล้ว — ถ้าต้องการเพิ่มบัญชี กรุณาสร้างผู้ใช้ KBiz ใหม่';

    public function selectable(): bool
    {
        return $this === self::New || $this === self::Reattachable;
    }

    /**
     * Shown next to the account in the list; also the error when a
     * non-selectable account is posted anyway.
     */
    public function note(): ?string
    {
        return match ($this) {
            self::New => null,
            self::Reattachable => 'เคยลงทะเบียนไว้แล้วแต่เซสชัน K BIZ หมดอายุ: จะเชื่อมต่อบัญชีเดิมอีกครั้งด้วย account id เดิม',
            self::Held => 'บัญชีนี้ถูกระงับ ติดต่อผู้ดูแล',
            self::Registered => 'บัญชีนี้ลงทะเบียนแล้ว ติดต่อผู้ดูแล',
            self::UserBound => self::MSG_USER_BOUND,
        };
    }
}
