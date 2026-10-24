<?php

namespace Tests\Unit;

use App\Security\AccountNumber;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AccountNumberTest extends TestCase
{
    public function test_normalises_formatting_to_digits(): void
    {
        $this->assertSame('1234567890', AccountNumber::tryFrom('123-4-56789-0')?->digits);
        $this->assertSame('1234567890', AccountNumber::tryFrom('123 4 56789 0')?->digits);
        $this->assertSame('1234567890', AccountNumber::tryFrom(1234567890)?->digits);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidNumbers(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
        yield 'letters' => ['12345abc90'];
        yield 'too short' => ['12345'];
        yield 'too long' => [str_repeat('1', 21)];
        yield 'leading dash' => ['-1234567890'];
        yield 'thai digits' => ['๑๒๓๔๕๖๗๘๙๐'];
        yield 'array' => [['1234567890']];
        yield 'float' => [1234567890.0];
        yield 'trailing newline' => ["1234567890\n"];
    }

    #[DataProvider('invalidNumbers')]
    public function test_rejects_invalid_input(mixed $raw): void
    {
        $this->assertNull(AccountNumber::tryFrom($raw));
    }

    public function test_masks_ten_digit_numbers_in_bank_grouping(): void
    {
        $this->assertSame('xxx-x-x6789-x', AccountNumber::tryFrom('1234567890')?->masked());
    }

    public function test_masks_other_lengths_to_last_four(): void
    {
        $this->assertSame('xxxx4567', AccountNumber::tryFrom('01234567')?->masked());
        $masked = AccountNumber::tryFrom(str_repeat('9', 20))?->masked();
        $this->assertSame(str_repeat('x', 16).'9999', $masked);
        $this->assertLessThanOrEqual(32, strlen((string) $masked));
    }
}
