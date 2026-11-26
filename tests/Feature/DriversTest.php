<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Sleep;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);

    config([
        'scanner-guard.http.url' => 'https://central.test/scanner-guard/bans',
        'scanner-guard.http.secret' => 'shared-secret',
    ]);
});

/**
 * @return array{0: string, 1: array<string, string>}
 */
function signedBan(ScannerGuard $scannerGuard, array $overrides = [], ?int $timestamp = null): array
{
    $body = (string) json_encode(array_merge([
        'ip' => '198.51.100.7',
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'wp-admin*',
        'hit_count' => 3,
        'path' => 'wp-admin',
        'banned_at' => now()->toIso8601String(),
        'expires_at' => now()->addDay()->toIso8601String(),
    ], $overrides));
    $timestamp = (string) ($timestamp ?? now()->timestamp);

    return [$body, [
        'X-Timestamp' => $timestamp,
        'X-Signature' => $scannerGuard->sign($timestamp, $body),
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
    ]];
}

function postBan(array $signed)
{
    [$body, $headers] = $signed;

    // call() ignores withHeaders(), so pass them as server vars.
    $server = collect($headers)
        ->mapWithKeys(fn ($value, $key) => ['HTTP_'.strtoupper(str_replace('-', '_', $key)) => $value])
        ->put('CONTENT_TYPE', 'application/json')
        ->all();

    return test()->call('POST', '/scanner-guard/bans', [], [], [], $server, $body);
}

function enableServerRoute(): void
{
    config(['scanner-guard.http.server.enabled' => true]);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
}

it('keeps cache-driver bans in the cache only, with no database writes', function () {
    config(['scanner-guard.driver' => 'cache']);
    $ip = '10.20.0.1';

    expect($this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3))->toBeNull();
    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
    expect(ScannerGuardBan::query()->count())->toBe(0);

    Cache::flush();

    expect($this->scannerGuard->isBanned($ip))->toBeFalse();
});

it('caches a database miss so non-banned ips skip the query, and ban() overrides it', function () {
    $ip = '10.20.0.6';

    DB::enableQueryLog();
    expect($this->scannerGuard->isBanned($ip))->toBeFalse();
    expect($this->scannerGuard->isBanned($ip))->toBeFalse();
    expect(DB::getQueryLog())->toHaveCount(1);

    $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
});

it('forwards http-driver bans with a valid hmac signature after the response', function () {
    config(['scanner-guard.driver' => 'http']);
    Http::fake();
    $this->withoutDefer();

    $ip = '10.20.0.2';

    expect($this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3, 'wp-admin'))->toBeNull();
    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
    expect(ScannerGuardBan::query()->count())->toBe(0);

    Http::assertSent(function (Request $request) use ($ip): bool {
        $timestamp = $request->header('X-Timestamp')[0];

        return $request->url() === 'https://central.test/scanner-guard/bans'
            && $request['ip'] === $ip
            && $request['hit_count'] === 3
            && $request->header('X-Signature')[0] === $this->scannerGuard->sign($timestamp, $request->body());
    });
});

it('forwards a ban made during a request, although that response is a 404', function () {
    config(['scanner-guard.driver' => 'http']);
    Http::fake();
    Route::get('/wp-admin', fn () => 'ok')->middleware('scanner-guard');

    foreach (range(1, 3) as $ignored) {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '10.20.0.9'])->get('/wp-admin');
    }

    $response->assertNotFound();
    Http::assertSent(fn (Request $request): bool => $request['ip'] === '10.20.0.9');
});

it('never lets a failing remote call break the ban', function () {
    config(['scanner-guard.driver' => 'http']);
    Http::fake(fn () => throw new RuntimeException('connection refused'));
    $this->withoutDefer();

    $ip = '10.20.0.3';
    $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
});

it('records a signed forwarded ban on the central app', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard))->assertCreated();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->ip_hash)->toBe($this->scannerGuard->hashIp('198.51.100.7'));
    expect($this->scannerGuard->rawIpFor($ban->ip_hash))->toBe('198.51.100.7');
    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeTrue();
    expect($this->scannerGuard->dailyStats(1)->last()['bans_count'])->toBe(1);
});

it('forwards the satellite offense and stores it on the central app', function () {
    config(['scanner-guard.driver' => 'http', 'scanner-guard.escalation' => [86400, 604800]]);
    Http::fake();
    $this->withoutDefer();

    $this->scannerGuard->ban('10.20.0.5', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Http::assertSent(fn (Request $request): bool => $request['offense'] === 1);

    config(['scanner-guard.driver' => 'database']);
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['offense' => 3]))->assertCreated();

    expect(ScannerGuardBan::query()->sole()->offense)->toBe(3);
});

it('forwards the satellite source and stores it on the central app', function () {
    config(['scanner-guard.driver' => 'http', 'app.name' => 'Shop']);
    Http::fake();
    $this->withoutDefer();

    $this->scannerGuard->ban('10.20.0.7', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    config(['scanner-guard.http.source' => 'blog']);
    $this->scannerGuard->ban('10.20.0.8', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Http::assertSent(fn (Request $request): bool => $request['ip'] === '10.20.0.7' && $request['source'] === 'Shop');
    Http::assertSent(fn (Request $request): bool => $request['ip'] === '10.20.0.8' && $request['source'] === 'blog');

    config(['scanner-guard.driver' => 'database']);
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['source' => 'blog']))->assertCreated();
    $this->scannerGuard->ban('10.20.0.9', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(ScannerGuardBan::query()->pluck('source', 'ip_hash')->all())->toBe([
        $this->scannerGuard->hashIp('198.51.100.7') => 'blog',
        $this->scannerGuard->hashIp('10.20.0.9') => null,
    ]);
});

it('only accepts a source listed in http.secrets when signed with its own secret', function () {
    config(['scanner-guard.http.secrets' => ['shop' => 'shop-secret']]);
    enableServerRoute();

    $sign = function (array $payload, string $secret): array {
        [$body, $headers] = signedBan($this->scannerGuard, $payload);
        $headers['X-Signature'] = $this->scannerGuard->sign($headers['X-Timestamp'], $body, $secret);

        return [$body, $headers];
    };

    // The shared secret can't forge a listed source.
    postBan($sign(['source' => 'shop'], 'shared-secret'))->assertForbidden();
    postBan($sign(['source' => 'shop'], 'shop-secret'))->assertCreated();

    // Unlisted sources fall back to the shared secret, and are refused once it's empty.
    postBan($sign(['ip' => '198.51.100.8', 'source' => 'blog'], 'shared-secret'))->assertCreated();
    config(['scanner-guard.http.secret' => null]);
    postBan($sign(['ip' => '198.51.100.9', 'source' => 'blog'], ''))->assertForbidden();

    expect(ScannerGuardBan::query()->pluck('source')->sort()->values()->all())->toBe(['blog', 'shop']);
});

it('reads the forwarded ban from the signed body only, never the query string', function () {
    config(['scanner-guard.http.secrets' => ['shop' => 'shop-secret']]);
    enableServerRoute();

    // Signed with the shared secret, no source in the body: a query source must not sneak in.
    [$body, $headers] = signedBan($this->scannerGuard);
    $server = collect($headers)->mapWithKeys(fn ($value, $key) => ['HTTP_'.strtoupper(str_replace('-', '_', $key)) => $value])->all();

    $this->call('POST', '/scanner-guard/bans?source=shop&offense=9', [], [], [], $server + ['CONTENT_TYPE' => 'application/json'], $body)
        ->assertCreated();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->source)->toBeNull();
    expect($ban->offense)->toBeNull();
});

it('stores one row when replicas sharing a source forward the same burst', function (array $source) {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['hit_count' => 3] + $source))->assertCreated();
    postBan(signedBan($this->scannerGuard, ['hit_count' => 4] + $source))->assertCreated();

    expect(ScannerGuardBan::query()->sole()->hit_count)->toBe(3);
})->with(['no source' => [[]], 'same source' => [['source' => 'shop']]]);

it('stores one row per source when several servers are hit at once', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['source' => 'shop']))->assertCreated();
    postBan(signedBan($this->scannerGuard, ['source' => 'blog']))->assertCreated();

    expect(ScannerGuardBan::query()->orderBy('id')->pluck('source')->all())->toBe(['shop', 'blog']);
});

it('accepts a fresh ban from every source right after an unban', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['source' => 'shop']))->assertCreated();
    postBan(signedBan($this->scannerGuard, ['source' => 'blog']))->assertCreated();
    expect($this->scannerGuard->unban($this->scannerGuard->hashIp('198.51.100.7')))->toBe(2);

    postBan(signedBan($this->scannerGuard, ['source' => 'shop', 'hit_count' => 5]))->assertCreated();
    postBan(signedBan($this->scannerGuard, ['source' => 'blog', 'hit_count' => 5]))->assertCreated();

    expect(ScannerGuardBan::query()->count())->toBe(2);
});

it('keeps the longest ban cached when another source forwards a shorter one', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['source' => 'shop', 'expires_at' => now()->addDays(30)->toIso8601String()]))->assertCreated();
    postBan(signedBan($this->scannerGuard, ['source' => 'blog', 'expires_at' => now()->addDay()->toIso8601String()]))->assertCreated();

    $this->travel(2)->days();

    expect($this->scannerGuard->rawIpFor($this->scannerGuard->hashIp('198.51.100.7')))->toBe('198.51.100.7');
});

it('never keeps the burst guard longer than a forwarded ban', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['source' => 'shop', 'expires_at' => now()->addSeconds(10)->toIso8601String()]))->assertCreated();
    $this->travel(11)->seconds();
    postBan(signedBan($this->scannerGuard, ['source' => 'shop']))->assertCreated();

    expect(ScannerGuardBan::query()->count())->toBe(2);
});

it('caches and inserts a ban under a per-ip lock, released afterwards', function () {
    $hash = $this->scannerGuard->hashIp('198.51.100.7');
    $lock = fn () => $this->scannerGuard->cache()->getStore()->lock("scanner-guard:ban-lock:{$hash}");
    $free = [];
    ScannerGuardBan::retrieved(function () use (&$free, $lock) {
        $free['read'] = $lock()->get();
    });
    ScannerGuardBan::creating(function () use (&$free, $lock) {
        $free['insert'] = $lock()->get();
    });

    $this->scannerGuard->recordForwardedBan('198.51.100.7', 'r', 'm', 1, now(), now()->addDay(), source: 'shop');
    $this->scannerGuard->recordForwardedBan('198.51.100.7', 'r', 'm', 1, now(), now()->addHour(), source: 'blog');

    expect($free)->toBe(['insert' => false, 'read' => false])
        ->and($lock()->get())->toBeTrue();
});

it('does not let a shorter local ban cut a longer forwarded one short', function () {
    $this->scannerGuard->recordForwardedBan('198.51.100.7', 'r', 'm', 1, now(), now()->addDays(30), source: 'shop');
    $this->scannerGuard->ban('198.51.100.7', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->travel(2)->days();

    expect($this->scannerGuard->rawIpFor($this->scannerGuard->hashIp('198.51.100.7')))->toBe('198.51.100.7');
});

it('still stores a ban when its lock cannot be acquired in time', function () {
    Sleep::fake(syncWithCarbon: true);
    $hash = $this->scannerGuard->hashIp('198.51.100.7');
    $this->scannerGuard->cache()->getStore()->lock("scanner-guard:ban-lock:{$hash}", 60)->get();

    $this->scannerGuard->recordForwardedBan('198.51.100.7', 'r', 'm', 1, now(), now()->addDay(), source: 'shop');

    expect(ScannerGuardBan::query()->count())->toBe(1);
});

it('stores the forwarded path on the central app when details are on', function () {
    config(['scanner-guard.store_details' => true]);
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['path' => 'wp-admin/setup-config.php?token=secret']))->assertCreated();

    expect(ScannerGuardBan::query()->sole()->path)->toBe('wp-admin/setup-config.php');
});

it('stores the evidence of an agent ban encrypted when details are on', function () {
    config(['scanner-guard.store_details' => true]);
    enableServerRoute();
    $evidence = ['<ip> - [25/Nov/2026:22:19:53 -0300] "GET /.env.staging HTTP/2.0" 403 rule=dotfile', 'Invalid user hari from <ip> port 44372'];

    postBan(signedBan($this->scannerGuard, ['evidence' => $evidence]))->assertCreated();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->evidence)->toBe($evidence)
        ->and($ban->toArray())->not->toHaveKey('evidence')
        ->and(DB::table('scanner_guard_bans')->value('evidence'))->not->toContain('.env.staging');
});

it('stores no evidence when details are off, or when the agent sent none', function (bool $details, array $overrides) {
    config(['scanner-guard.store_details' => $details]);
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, $overrides))->assertCreated();

    expect(ScannerGuardBan::query()->sole()->evidence)->toBeNull();
})->with([
    'details off' => [false, ['evidence' => ['GET /.env']]],
    'older agent' => [true, []],
    'empty list' => [true, ['evidence' => []]],
]);

it('still stores the ban when the evidence migration has not run yet', function () {
    Schema::table('scanner_guard_bans', fn (Blueprint $table) => $table->dropColumn('evidence'));
    config(['scanner-guard.store_details' => true]);
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['evidence' => ['GET /.env']]))->assertCreated();

    expect(ScannerGuardBan::query()->sole()->path)->toBe('wp-admin');
});

it('rejects evidence that is not a short list of strings', function (mixed $evidence) {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard, ['evidence' => $evidence]))->assertUnprocessable();

    expect(ScannerGuardBan::query()->count())->toBe(0);
})->with([
    'too many lines' => [array_fill(0, 21, 'x')],
    'line too long' => [[str_repeat('x', 1025)]],
    'not a list' => [['a' => 'x']],
    'not strings' => [[['x']]],
    'a string' => ['x'],
]);

it('rejects forwarded bans with a bad signature, a stale timestamp or a replay', function () {
    enableServerRoute();

    [$body, $headers] = signedBan($this->scannerGuard);
    postBan([$body, ['X-Signature' => 'nope'] + $headers])->assertForbidden();

    postBan(signedBan($this->scannerGuard, [], now()->subMinutes(10)->timestamp))->assertForbidden();

    $signed = signedBan($this->scannerGuard);
    postBan($signed)->assertCreated();
    postBan($signed)->assertStatus(409);

    expect(ScannerGuardBan::query()->count())->toBe(1);
});

it('rejects an unknown driver before touching the cache', function () {
    config(['scanner-guard.driver' => 'redis']);

    expect(fn () => $this->scannerGuard->ban('10.20.0.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3))
        ->toThrow(InvalidArgumentException::class);
    expect($this->scannerGuard->isBanned('10.20.0.4'))->toBeFalse();
});

it('does not consume the signature of a payload that fails validation', function () {
    enableServerRoute();

    $signed = signedBan($this->scannerGuard, ['ip' => 'not-an-ip']);

    postBan($signed)->assertUnprocessable();
    postBan($signed)->assertUnprocessable();
});

it('does not register the receiving route unless enabled', function () {
    postBan(signedBan($this->scannerGuard))->assertNotFound();
});

it('skips the database-only commands and schedule for other drivers', function () {
    config(['scanner-guard.driver' => 'cache']);

    $this->artisan('scanner-guard:aggregate-and-prune')->expectsOutputToContain('Skipped')->assertSuccessful();
    $this->artisan('scanner-guard:sync-denylist')->expectsOutputToContain('Skipped')->assertSuccessful();

    putenv('SCANNER_GUARD_DRIVER=cache');
    $_ENV['SCANNER_GUARD_DRIVER'] = 'cache';

    try {
        $this->refreshApplication();

        $event = collect(app(Schedule::class)->events())->first(
            fn ($event) => str_contains($event->command ?? '', 'scanner-guard:')
        );

        expect($event)->toBeNull();
    } finally {
        putenv('SCANNER_GUARD_DRIVER');
        unset($_ENV['SCANNER_GUARD_DRIVER']);
    }
});
