<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\VisitorFingerprint\VisitorFingerprintServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [
            VisitorFingerprintServiceProvider::class,
            ScannerGuardServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', $this->testing_connection());
        $app['config']->set('cache.default', 'array');
    }

    protected function defineDatabaseMigrations(): void
    {
        $tempPath = sys_get_temp_dir().'/laravel-scanner-guard-migrations';

        if (! is_dir($tempPath)) {
            mkdir($tempPath, 0755, true);
        }

        copy(
            __DIR__.'/../database/migrations/create_scanner_guard_bans_table.php.stub',
            $tempPath.'/0001_01_01_000000_create_scanner_guard_bans_table.php'
        );
        copy(
            __DIR__.'/../database/migrations/create_scanner_guard_ban_daily_stats_table.php.stub',
            $tempPath.'/0001_01_01_000001_create_scanner_guard_ban_daily_stats_table.php'
        );

        $this->loadMigrationsFrom($tempPath);
    }

    /**
     * The original in-memory SQLite connection by default; CI (tests.yml) sets
     * SCANNER_GUARD_TEST_DB_* to run the same suite on MySQL and PostgreSQL. Not DB_CONNECTION:
     * Testbench pins it to "testing", which would always win over a driver read from it.
     *
     * @return array<string, mixed>
     */
    protected function testing_connection(): array
    {
        $driver = env('SCANNER_GUARD_TEST_DB_DRIVER', 'sqlite');

        if ($driver === 'sqlite') {
            return [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ];
        }

        return [
            'driver' => $driver,
            'host' => env('SCANNER_GUARD_TEST_DB_HOST', '127.0.0.1'),
            'port' => env('SCANNER_GUARD_TEST_DB_PORT'),
            'database' => env('SCANNER_GUARD_TEST_DB_DATABASE', 'testing'),
            'username' => env('SCANNER_GUARD_TEST_DB_USERNAME', 'root'),
            'password' => env('SCANNER_GUARD_TEST_DB_PASSWORD', ''),
            'charset' => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'prefix' => '',
        ];
    }
}
