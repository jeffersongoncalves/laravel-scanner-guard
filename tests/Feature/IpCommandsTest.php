<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

function ipList(string $contents): string
{
    $file = tempnam(sys_get_temp_dir(), 'sg');
    file_put_contents($file, $contents);

    return $file;
}

it('imports bans, compressing IPv6 and skipping the never-block list', function () {
    config(['scanner-guard.ip_ignore' => ['198.51.100.0/24']]);
    $file = ipList("# bots\n203.0.113.5 extra columns\n203.0.113.5\n2001:0db8::0001\n198.51.100.9\nnope\n");

    $this->artisan('scanner-guard:import', ['file' => $file])
        ->expectsOutputToContain('2 new, 0 existing, 1 invalid, 1 ignored')
        ->assertSuccessful();

    $sg = app(ScannerGuard::class);
    expect($sg->isBanned('2001:db8::1'))->toBeTrue()
        ->and($sg->isBanned('203.0.113.5'))->toBeTrue()
        ->and(ScannerGuardBan::query()->pluck('reason')->unique()->all())->toBe([ScannerGuardBan::REASON_MANUAL]);
});

it('imports block and ignore entries, refusing ranges wider than /8', function () {
    $file = ipList("203.0.113.0/24\n10.0.0.0/7\n198.51.100.7\n");

    $this->artisan('scanner-guard:import', ['file' => $file, '--as' => 'block', '--note' => 'bots'])
        ->expectsOutputToContain('2 new, 0 existing, 1 invalid')
        ->assertSuccessful();
    $this->artisan('scanner-guard:import', ['file' => $file, '--as' => 'ignore'])->assertSuccessful();
    $this->artisan('scanner-guard:import', ['file' => $file, '--as' => 'block'])
        ->expectsOutputToContain('0 new, 2 existing')
        ->assertSuccessful();

    expect(ScannerGuardBlocklistEntry::query()->where('type', 'ip')->pluck('note', 'value')->all())
        ->toEqual(['203.0.113.0/24' => 'bots', '198.51.100.7' => 'bots'])
        ->and(ScannerGuardBlocklistEntry::query()->where('type', 'ignore')->count())->toBe(2)
        ->and(app(ScannerGuard::class)->ipBlocklist())->toContain('203.0.113.0/24');
});

it('rejects an unknown --as and an unreadable file', function () {
    $this->artisan('scanner-guard:import', ['file' => ipList(''), '--as' => 'nuke'])->assertFailed();
    $this->artisan('scanner-guard:import', ['file' => '/nonexistent/list.txt'])->assertFailed();
});

it('groups stored ban IPs by /24 and /16, flagging blocked ranges', function () {
    config(['scanner-guard.store_details' => true, 'scanner-guard.ip_blocklist' => ['203.0.113.0/24']]);
    $sg = app(ScannerGuard::class);

    foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.5.1'] as $ip) {
        $sg->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    }

    $this->artisan('scanner-guard:ban-report')
        ->expectsTable(['Range', 'IPs', 'Bans', 'Sources', 'Reasons', 'Period', 'Blocked'], [
            ['203.0.113.0/24', 3, 3, 1, 'scanner_path', now()->format('Y-m-d').' to '.now()->format('Y-m-d'), 'yes'],
        ])
        ->expectsTable(['Range', 'IPs', 'Bans', 'Sources', 'Reasons', 'Period', 'Blocked'], [
            ['203.0.0.0/16', 4, 4, 1, 'scanner_path', now()->format('Y-m-d').' to '.now()->format('Y-m-d'), ''],
        ])
        ->assertSuccessful();
});

it('explains an empty ban report without store_details', function () {
    app(ScannerGuard::class)->ban('203.0.113.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:ban-report')->expectsOutputToContain('store_details')->assertSuccessful();
});

it('looks up the banned IPs of a range with whois', function () {
    config(['scanner-guard.store_details' => true]);
    app(ScannerGuard::class)->ban('203.0.113.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    app(ScannerGuard::class)->ban('198.51.100.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    Process::fake(['*' => Process::result("OrgName:  Example Hosting\nNetName: EX-NET\nCountry: us\n")]);

    $this->artisan('scanner-guard:whois', ['network' => '203.0.113.0/24'])
        ->expectsTable(['IP', 'Bans', 'Reasons', 'Owner', 'Network', 'Country'], [
            ['203.0.113.1', 1, 'scanner_path', 'Example Hosting', 'EX-NET', 'US'],
        ])
        ->assertSuccessful();

    Process::assertRanTimes(fn ($process) => $process->command === ['whois', '203.0.113.1'], 1);
});
