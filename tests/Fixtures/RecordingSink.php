<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Tests\Fixtures;

use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;

class RecordingSink implements DenylistSink
{
    /** @var list<list<array{ip: string, reason: string, expires_at: string|null}>> */
    public static array $calls = [];

    public static ?string $throw = null;

    public function sync(array $entries): void
    {
        if (self::$throw !== null) {
            throw new \RuntimeException(self::$throw);
        }

        self::$calls[] = $entries;
    }

    /**
     * @return list<array{ip: string, reason: string, expires_at: string|null}>
     */
    public static function last(): array
    {
        return self::$calls[array_key_last(self::$calls)] ?? [];
    }

    public static function reset(): void
    {
        self::$calls = [];
        self::$throw = null;
    }
}
