<?php

namespace App\Wrapbiz;

/**
 * Text returned by registration_code_usable(). Customers already hold the
 * code, so telling them which state it is in reveals nothing to a guesser.
 */
enum CodeStatus: string
{
    case Usable = 'usable';
    case Unknown = 'unknown';
    case Used = 'used';
    case Expired = 'expired';
    case Locked = 'locked';
    case Exhausted = 'exhausted';

    public function message(): string
    {
        return match ($this) {
            self::Usable => '',
            self::Unknown => 'รหัสลงทะเบียนไม่ถูกต้อง กรุณาตรวจสอบแล้วลองอีกครั้ง',
            self::Used => 'รหัสลงทะเบียนนี้ถูกใช้แล้ว การลงทะเบียนอาจเสร็จสมบูรณ์ไปแล้ว (เช่น จากการกดซ้ำหรือจากแท็บอื่น) กรุณาติดต่อผู้ดูแลระบบเพื่อตรวจสอบ',
            self::Expired => 'รหัสลงทะเบียนนี้หมดอายุแล้ว ไม่มีการบันทึกข้อมูลใด ๆ กรุณาติดต่อผู้ดูแลระบบเพื่อขอรหัสใหม่',
            self::Locked => 'รหัสลงทะเบียนนี้ถูกล็อกเนื่องจากเข้าสู่ระบบ K BIZ ไม่สำเร็จหลายครั้ง กรุณาติดต่อผู้ดูแลระบบเพื่อขอรหัสใหม่',
            self::Exhausted => 'โค้ดนี้ใช้ตรวจสอบบัญชีครบจำนวนแล้ว ติดต่อผู้ดูแลเพื่อขอโค้ดใหม่',
        };
    }
}
