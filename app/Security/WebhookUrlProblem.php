<?php

namespace App\Security;

enum WebhookUrlProblem
{
    case TooLong;
    case Malformed;
    case NotHttps;
    case HasCredentials;
    case HasFragment;
    case WrongPort;
    case InvalidHost;
    case DoesNotResolve;
    case NotPublic;

    public function message(): string
    {
        return match ($this) {
            self::TooLong => 'URL ยาวเกิน 2,048 ตัวอักษร',
            self::Malformed => 'รูปแบบ URL ไม่ถูกต้อง (ห้ามมีช่องว่าง เครื่องหมาย \\ หรืออักขระที่ไม่ใช่ ASCII ให้เข้ารหัสแบบ %XX ให้ถูกต้อง)',
            self::NotHttps => 'URL ต้องขึ้นต้นด้วย https://',
            self::HasCredentials => 'URL ห้ามมีชื่อผู้ใช้หรือรหัสผ่าน (user:pass@)',
            self::HasFragment => 'URL ห้ามมีส่วน # (fragment)',
            self::WrongPort => 'ระบบส่ง webhook ได้เฉพาะพอร์ต 443 กรุณาลบส่วน :พอร์ต ออกจาก URL (หรือระบุเป็น :443)',
            self::InvalidHost => 'ชื่อโดเมนไม่ถูกต้อง (โดเมนภาษาไทยให้ใช้รูปแบบ punycode xn--)',
            self::DoesNotResolve => 'ไม่พบ IP ของโดเมนนี้ กรุณาตรวจสอบ DNS',
            self::NotPublic => 'โดเมนนี้ชี้ไปยัง IP ภายในหรือ IP ที่ไม่ใช่สาธารณะ ระบบส่ง webhook ได้เฉพาะเซิร์ฟเวอร์ที่เข้าถึงได้จากอินเทอร์เน็ต',
        };
    }
}
