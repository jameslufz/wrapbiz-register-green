<?php

namespace Tests\Unit;

use App\Wrapbiz\CodeStatus;
use PHPUnit\Framework\TestCase;

final class CodeStatusTest extends TestCase
{
    public function test_every_unusable_status_has_a_thai_message(): void
    {
        foreach (CodeStatus::cases() as $status) {
            if ($status !== CodeStatus::Usable) {
                $this->assertMatchesRegularExpression('/\p{Thai}/u', $status->message());
            }
        }
    }

    public function test_only_expired_claims_nothing_was_saved(): void
    {
        $this->assertStringContainsString('ไม่มีการบันทึก', CodeStatus::Expired->message());
        $this->assertStringNotContainsString('ไม่มีการบันทึก', CodeStatus::Used->message());
        $this->assertStringContainsString('ติดต่อผู้ดูแลระบบ', CodeStatus::Used->message());
    }
}
