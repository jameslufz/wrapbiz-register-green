<?php

namespace App\Kbiz;

enum BankFailure: string
{
    case Unreachable = 'unreachable';
    case HttpError = 'http_error';
    case UnexpectedResponse = 'unexpected_response';
    case Redirected = 'redirected';
    case LoginFailed = 'login_failed';
    case NoAccounts = 'no_accounts';

    public function message(): string
    {
        return match ($this) {
            self::Unreachable, self::HttpError => 'ไม่สามารถเชื่อมต่อธนาคารได้ในขณะนี้ กรุณาลองใหม่อีกครั้ง',
            self::UnexpectedResponse, self::Redirected => 'ธนาคารตอบกลับในรูปแบบที่ระบบไม่รู้จัก กรุณาลองใหม่อีกครั้ง หากยังพบปัญหาโปรดติดต่อผู้ดูแลระบบ',
            self::LoginFailed => 'เข้าสู่ระบบ K BIZ ไม่สำเร็จ กรุณาตรวจสอบชื่อผู้ใช้และรหัสผ่าน',
            self::NoAccounts => 'ไม่พบบัญชีที่ใช้งานได้ของผู้ใช้ K BIZ นี้',
        };
    }
}
