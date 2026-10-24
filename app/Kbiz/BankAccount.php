<?php

namespace App\Kbiz;

use App\Security\AccountNumber;

final readonly class BankAccount
{
    public function __construct(
        public AccountNumber $number,
        public string $kind,
    ) {}
}
