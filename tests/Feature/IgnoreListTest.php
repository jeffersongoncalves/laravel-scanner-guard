<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\ScannerGuard\Tests\Fixtures\RecordingSink;

beforeEach(function () {
    $this->guard = app(ScannerGuard::class);
    Route::get('/hello', fn () => 'ok')->middleware('scanner-guard');
    Route::get('/wp-login', fn () => 'ok')->middleware('scanner-guard');
});

function visitFrom(string $path, string $ip, string $userAgent = 'Mozilla/5.0')
{
    return test()->withServerVariables(['REMOTE_ADDR' => $ip])->get($path, ['User-Agent' => $userAgent]);
}

it('never blocks or bans an ignored ip, whatever it does', function (string $ip) {
    config([
        'scanner-guard.ip_ignore' => ['203.0.113.10', '10.9.0.0/16', '2001:db8::/32'],
        'scanner-guard.ip_blocklist' => [$ip],
        'scanner-guard.user_agent_blocklist.patterns' => ['sqlmap*'],
    ]);

    visitFrom('/hello', $ip)->assertOk();
    visitFrom('/hello', $ip, 'sqlmap/1.8')->assertOk();

    foreach (range(1, 5) as $hit) {
        visitFrom('/wp-login', $ip)->assertOk();
    }

    expect($this->guard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'x', 3))->toBeNull()
        ->and(ScannerGuardBan::query()->count())->toBe(0);
})->with(['203.0.113.10', '10.9.4.2', '2001:db8::1']);

it('still bans the ips outside the list', function () {
    config(['scanner-guard.ip_ignore' => ['203.0.113.10'], 'scanner-guard.ban_threshold' => 1]);

    visitFrom('/wp-login', '203.0.113.11')->assertNotFound();

    expect(ScannerGuardBan::query()->count())->toBe(1);
});

it('drops invalid entries and ranges that would exempt much of the internet', function () {
    config(['scanner-guard.ip_ignore' => ['0.0.0.0/0', '::/0', '128.0.0.0/1', '2000::/3', '10.0.0.0/7', 'nope', '10.0.0.0/', '1.2.3.4/33', '10.0.0.0/8', '2001:db8::/16', '203.0.113.10']]);

    expect($this->guard->ipIgnore())->toBe(['10.0.0.0/8', '2001:db8::/16', '203.0.113.10'])
        ->and($this->guard->isIpIgnored('198.51.100.1'))->toBeFalse();
});

it('reads runtime entries, applied on the next call', function () {
    expect($this->guard->isIpIgnored('203.0.113.10'))->toBeFalse();

    $entry = ScannerGuardBlocklistEntry::query()->create(['type' => ScannerGuardBlocklistEntry::TYPE_IGNORE, 'value' => '203.0.113.0/24']);
    expect($this->guard->isIpIgnored('203.0.113.10'))->toBeTrue()
        ->and($this->guard->isIpBlocked('203.0.113.10'))->toBeFalse();

    $entry->delete();
    expect($this->guard->isIpIgnored('203.0.113.10'))->toBeFalse();
});

it('lets in an ip banned before it was listed, and takes it off the denylist and the sinks', function () {
    RecordingSink::reset();
    config(['scanner-guard.ip_blocklist' => ['203.0.113.12', '203.0.113.0/24']]);
    $this->guard->ban('203.0.113.10', ScannerGuardBan::REASON_SCANNER_PATH, 'x', 3);
    $this->guard->ban('198.51.100.7', ScannerGuardBan::REASON_SCANNER_PATH, 'x', 3);
    config(['scanner-guard.ip_blocklist' => ['203.0.113.12', '192.0.2.0/24']]);

    visitFrom('/hello', '203.0.113.10')->assertNotFound();

    config(['scanner-guard.ip_ignore' => ['203.0.113.10', '203.0.113.12']]);

    visitFrom('/hello', '203.0.113.10')->assertOk();
    expect(array_column($this->guard->denylist()['bans'], 'ip'))->toBe(['198.51.100.7'])
        ->and(array_column($this->guard->denylistEntries(), 'ip'))->toBe(['192.0.2.0/24', '198.51.100.7']);
});

it('accepts a forwarded ban of an ignored ip without storing it', function () {
    config([
        'scanner-guard.http.server.enabled' => true,
        'scanner-guard.http.secret' => 'shared-secret',
        'scanner-guard.ip_ignore' => ['203.0.113.10'],
    ]);
    (new ScannerGuardServiceProvider(app()))->packageBooted();

    $payload = [
        'ip' => '203.0.113.10',
        'reason' => 'ssh_bruteforce',
        'matched_value' => 'x',
        'hit_count' => 5,
        'banned_at' => now()->toIso8601String(),
        'expires_at' => now()->addDay()->toIso8601String(),
        'source' => 'vps-01',
    ];
    $timestamp = (string) now()->timestamp;

    $this->postJson('/scanner-guard/bans', $payload, [
        'X-Timestamp' => $timestamp,
        'X-Signature' => $this->guard->sign($timestamp, (string) json_encode($payload)),
    ])->assertCreated();

    expect(ScannerGuardBan::query()->count())->toBe(0);
});

it('serves the list, as a json array even when empty', function () {
    config(['scanner-guard.ip_ignore' => ['0.0.0.0/0', '203.0.113.10']]);
    expect($this->guard->denylist()['ignore'])->toBe(['203.0.113.10']);

    config(['scanner-guard.ip_ignore' => ['0.0.0.0/0']]);
    expect(json_encode($this->guard->denylist()['ignore']))->toBe('[]');
});

it('pulls the list into a satellite: absent keeps the last one, empty clears it', function () {
    config(['scanner-guard.driver' => 'http', 'scanner-guard.http.url' => 'https://central.test/bans', 'scanner-guard.http.secret' => 's']);
    Http::fake(['central.test/*' => Http::sequence()
        ->push(['bans' => [], 'ignore' => ['203.0.113.10', '0.0.0.0/0', 7]])
        ->push(['bans' => []])
        ->push(['bans' => [], 'ignore' => []])]);

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();
    expect($this->guard->ipIgnore())->toBe(['203.0.113.10']);

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();
    expect($this->guard->ipIgnore())->toBe(['203.0.113.10']);

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();
    expect($this->guard->ipIgnore())->toBe([]);
});
