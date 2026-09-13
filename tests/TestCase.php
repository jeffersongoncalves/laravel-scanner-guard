<?php

namespace JeffersonGoncalves\ScannerGuard\Tests;

use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            ScannerGuardServiceProvider::class,
        ];
    }
}
