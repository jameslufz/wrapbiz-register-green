<?php

namespace App\Security;

/**
 * A bank account number normalised to digits, so the same account always
 * produces the same fingerprint no matter how the bank formats it.
 */
final readonly class AccountNumber
{
    private const int MIN_DIGITS = 6;

    private const int MAX_DIGITS = 20;

    private function __construct(public string $digits) {}

    public static function tryFrom(mixed $raw): ?self
    {
        if (! is_string($raw) && ! is_int($raw)) {
            return null;
        }

        $raw = (string) $raw;
        if (preg_match('/^[0-9][0-9 -]*$/D', $raw) !== 1) {
            return null;
        }

        $digits = str_replace([' ', '-'], '', $raw);
        $length = strlen($digits);

        return $length >= self::MIN_DIGITS && $length <= self::MAX_DIGITS ? new self($digits) : null;
    }

    /**
     * 10-digit KBank numbers use the bank's 3-1-5-1 grouping (xxx-x-x1234-x);
     * anything else shows only the last four digits.
     */
    public function masked(): string
    {
        if (strlen($this->digits) === 10) {
            return 'xxx-x-x'.substr($this->digits, 5, 4).'-x';
        }

        return str_repeat('x', strlen($this->digits) - 4).substr($this->digits, -4);
    }
}
