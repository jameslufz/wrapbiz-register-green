<?php

namespace App\Kbiz;

/**
 * One bank request, described entirely by env: where it goes, which static
 * headers it carries, how logical field names map to the bank's real key
 * names, and the fixed values some of those fields carry.
 */
final readonly class KbizStep
{
    /**
     * @param  array<string, string>  $headers
     * @param  array<string, string>  $fields  logical name → real key name
     * @param  array<string, scalar>  $values  logical name → real fixed value
     * @param  list<string>  $constants  logical names sent as field(name) => value(name) on every request
     */
    public function __construct(
        public string $name,
        public string $path,
        public array $headers,
        private array $fields,
        private array $values,
        private array $constants,
    ) {}

    public function field(string $logicalName): string
    {
        return $this->fields[$logicalName]
            ?? throw new KbizConfigException("Logical field \"{$logicalName}\" is not configured for step {$this->name}.");
    }

    public function value(string $logicalName): string
    {
        return array_key_exists($logicalName, $this->values)
            ? (string) $this->values[$logicalName]
            : throw new KbizConfigException("Logical value \"{$logicalName}\" is not configured for step {$this->name}.");
    }

    /**
     * @return array<string, string>
     */
    public function constantFields(): array
    {
        $body = [];
        foreach ($this->constants as $logicalName) {
            $body[$this->field($logicalName)] = $this->value($logicalName);
        }

        return $body;
    }
}
