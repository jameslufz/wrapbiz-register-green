<?php

namespace App\Wrapbiz;

use RuntimeException;

final class RegistrationRejected extends RuntimeException
{
    public function __construct(public readonly RejectionReason $reason)
    {
        parent::__construct("Registration rejected: {$reason->name}");
    }
}
