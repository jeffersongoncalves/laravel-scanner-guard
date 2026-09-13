<?php

namespace JeffersonGoncalves\ScannerGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \JeffersonGoncalves\ScannerGuard\ScannerGuard
 */
class ScannerGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-scanner-guard';
    }
}
