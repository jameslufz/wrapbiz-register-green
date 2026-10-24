<?php

namespace App\Wrapbiz;

use RuntimeException;

/**
 * Any database failure other than a business rejection. Deliberately carries
 * no previous exception: driver messages include the SQL and its bindings.
 */
final class RegistrationStoreUnavailable extends RuntimeException
{
    public function __construct(public readonly string $sqlState)
    {
        parent::__construct("wrapbiz database call failed (SQLSTATE {$sqlState})");
    }
}
