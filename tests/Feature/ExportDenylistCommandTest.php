<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Queue;
use JeffersonGoncalves\ScannerGuard\Jobs\ExportDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

afterEach(function () {
    File::deleteDirectory(storage_path('app/scanner-guard'));
});

it('writes active bans as nginx deny lines when the raw ip is still cached', function () {
    $ip = '10.20.20.20';
    app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:export-denylist', ['--path' => 'storage/app/scanner-guard/denylist-test.conf'])
        ->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist-test.conf'));
    expect($contents)->toContain("deny {$ip};");
});

it('skips bans whose raw ip is no longer cached, without failing the export', function () {
    $ip = '10.20.20.21';
    app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Cache::flush();

    $this->artisan('scanner-guard:export-denylist', ['--path' => 'storage/app/scanner-guard/denylist-test2.conf'])
        ->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist-test2.conf'));
    expect($contents)->not->toContain($ip);
});

it('defaults the path to scanner-guard.nginx.path and writes atomically', function () {
    config()->set('scanner-guard.nginx.path', 'storage/app/scanner-guard/configured.conf');
    app(ScannerGuard::class)->ban('10.20.20.22', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    expect(File::get(storage_path('app/scanner-guard/configured.conf')))->toContain('deny 10.20.20.22;')
        ->and(File::glob(storage_path('app/scanner-guard/*.tmp')))->toBe([]);
});

it('runs the reload command only when the file content changed', function () {
    Process::fake();
    config()->set('scanner-guard.nginx.reload_command', 'sudo nginx -s reload');
    app(ScannerGuard::class)->ban('10.20.20.23', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();
    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    Process::assertRanTimes('sudo nginx -s reload', 1);
});

it('logs instead of failing when the reload command fails', function () {
    Process::fake(['*' => Process::result(errorOutput: 'nginx: [emerg]', exitCode: 1)]);
    Log::spy();
    config()->set('scanner-guard.nginx.reload_command', 'sudo nginx -s reload');

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    Log::shouldHaveReceived('error')->withArgs(fn (string $message) => str_contains($message, 'nginx reload command failed'));
});

it('logs instead of failing when the reload command throws (e.g. a timeout)', function () {
    Process::fake(fn () => throw new RuntimeException('The process exceeded the timeout of 60 seconds.'));
    Log::spy();
    config()->set('scanner-guard.nginx.reload_command', 'sudo nginx -s reload');

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    Log::shouldHaveReceived('error')->withArgs(fn (string $message, array $context) => str_contains($context['error'], 'timeout'));
});

it('releases the export lock so the next export can run', function () {
    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    expect(app(ScannerGuard::class)->cache()->getStore()->lock('scanner-guard:export-denylist')->get())->toBeTrue();
});

it('writes valid ip_blocklist entries as static deny lines and skips invalid ones', function () {
    config()->set('scanner-guard.ip_blocklist', ['185.177.72.69', '185.177.72.0/24', '2001:db8::/32', 'not-an-ip', '10.0.0.0/33', '1.2.3.4; allow all']);
    Cache::flush();

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist.conf'));
    expect($contents)->toContain('deny 185.177.72.69; # static')
        ->toContain('deny 185.177.72.0/24; # static')
        ->toContain('deny 2001:db8::/32; # static')
        ->not->toContain('not-an-ip')
        ->not->toContain('/33')
        ->not->toContain('allow all');
});

it('writes one deny line per ip, keeping the latest expiry of escalated bans', function () {
    config(['scanner-guard.escalation' => [86400, 604800]]);
    $guard = app(ScannerGuard::class);
    $guard->ban('10.20.20.30', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(2)->minutes(); // past the burst guard
    $guard->ban('10.20.20.30', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $latest = ScannerGuardBan::query()->max('expires_at');
    expect(ScannerGuardBan::query()->active()->count())->toBe(2)
        ->and(ScannerGuardBan::query()->min('expires_at'))->not->toBe($latest);

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist.conf'));
    expect(substr_count($contents, 'deny 10.20.20.30;'))->toBe(1)
        ->and($contents)->toContain(ScannerGuardBan::query()->orderByDesc('expires_at')->first()->expires_at->toIso8601String());
});

it('writes only the static line for an ip that is also banned', function () {
    config()->set('scanner-guard.ip_blocklist', ['10.20.20.31']);
    app(ScannerGuard::class)->ban('10.20.20.31', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:export-denylist')->assertSuccessful();

    expect(File::get(storage_path('app/scanner-guard/denylist.conf')))->toBe('deny 10.20.20.31; # static'.PHP_EOL);
});

it('queues an export on every ban when sync_to_nginx is on', function () {
    Queue::fake();
    config()->set('scanner-guard.sync_to_nginx', true);

    app(ScannerGuard::class)->ban('10.20.20.24', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Queue::assertPushed(ExportDenylist::class);
});

it('does not queue an export when sync_to_nginx or export_on_ban is off', function () {
    Queue::fake();
    app(ScannerGuard::class)->ban('10.20.20.25', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    config()->set('scanner-guard.sync_to_nginx', true);
    config()->set('scanner-guard.nginx.export_on_ban', false);
    app(ScannerGuard::class)->ban('10.20.20.26', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Queue::assertNothingPushed();
});

it('updates the denylist file right after a ban on the sync queue', function () {
    config()->set('scanner-guard.sync_to_nginx', true);

    app(ScannerGuard::class)->ban('10.20.20.27', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(File::get(storage_path('app/scanner-guard/denylist.conf')))->toContain('deny 10.20.20.27;');
});
