<?php

namespace JeffersonGoncalves\ScannerGuard;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ScannerGuardServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-scanner-guard')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigrations();
    }
}
