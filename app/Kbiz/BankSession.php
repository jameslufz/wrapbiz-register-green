<?php

namespace App\Kbiz;

/**
 * The logged-in bank session the worker polls with. Sealed for the worker
 * at the end of registration; never shown to the browser.
 */
final readonly class BankSession
{
    public function __construct(
        #[\SensitiveParameter] public string $sessionToken,
        public string $userRef,
        public string $orgId,
        public string $customerType,
    ) {}

    /**
     * Key names are the contract with the worker's sealed-credential reader.
     *
     * @return array{session_token: string, user_ref: string, org_id: string, customer_type: string}
     */
    public function toArray(): array
    {
        return [
            'session_token' => $this->sessionToken,
            'user_ref' => $this->userRef,
            'org_id' => $this->orgId,
            'customer_type' => $this->customerType,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return new self(
            (string) ($data['session_token'] ?? ''),
            (string) ($data['user_ref'] ?? ''),
            (string) ($data['org_id'] ?? ''),
            (string) ($data['customer_type'] ?? ''),
        );
    }
}
