<?php

namespace App\Kbiz;

use RuntimeException;

/**
 * A failed bank call. The message is fixed per failure kind and step and never
 * carries bank output, request data or the underlying exception (which may
 * contain response snippets or credentials).
 */
final class BankException extends RuntimeException
{
    /**
     * @param  bool  $failedCredentialSubmit  the bank answered a credential submission with anything but a QR challenge
     */
    public function __construct(
        public readonly BankFailure $failure,
        public readonly string $step,
        public readonly bool $failedCredentialSubmit = false,
    ) {
        parent::__construct("KBiz step {$step} failed: {$failure->value}");
    }
}
