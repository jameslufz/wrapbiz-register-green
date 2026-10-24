<?php

namespace App\Registration;

enum Stage: string
{
    case CodeAccepted = 'code_accepted';
    case AwaitingApproval = 'awaiting_approval';
    case ChoosingAccounts = 'choosing_accounts';

    public function route(): string
    {
        return match ($this) {
            self::CodeAccepted => 'registration.login',
            self::AwaitingApproval => 'registration.approve',
            self::ChoosingAccounts => 'registration.accounts',
        };
    }
}
