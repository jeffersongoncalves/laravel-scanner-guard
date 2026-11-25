<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);

    config([
        'scanner-guard.driver' => 'http',
        'scanner-guard.http.url' => 'https://central.test/scanner-guard/bans',
        'scanner-guard.http.secret' => 'shared-secret',
        'scanner-guard.http.source' => 'shop',
    ]);
});

const SIGNED_BODY = '{"bans":[],"ip_blocklist":["185.177.72.69"],"user_agent_patterns":[]}';

/**
 * Answers the pull with SIGNED_BODY and the headers $headers(request) returns.
 */
function fakeSignedCentral(callable $headers, string $body = SIGNED_BODY): void
{
    Http::fake(['central.test/*' => fn (Request $request) => Http::response($body, 200, $headers($request))]);
}

/**
 * @return array<string, string>
 */
function signedHeaders(Request $request, array $override = []): array
{
    $values = $override + [
        'timestamp' => (string) now()->timestamp,
        'request' => $request->header('X-Signature')[0],
        'source' => 'shop',
        'body' => SIGNED_BODY,
        'secret' => 'shared-secret',
    ];

    return [
        'X-Timestamp' => $values['timestamp'],
        'X-Signature' => app(ScannerGuard::class)->signResponse($values['timestamp'], $values['request'], $values['source'], $values['body'], $values['secret']),
    ];
}

// Same vector as scanner-guard-agent's TestVerifyMatchesPHP.
it('signs a response over a fixed, newline-separated layout', function () {
    expect($this->scannerGuard->signResponse('1700000000', str_repeat('a', 64), 'vps-01', '{"bans":[]}', 'secret'))
        ->toBe(hash_hmac('sha256', "response\n1700000000\n".str_repeat('a', 64)."\nvps-01\n{\"bans\":[]}", 'secret'))
        ->toBe('1ad7189f847c000414df825a35600c719979793f0d3330d895e9f989d073bac6');
});

it('signs the denylist response with the secret of the source, bound to the request', function () {
    config([
        'scanner-guard.driver' => 'database',
        'scanner-guard.http.server.enabled' => true,
        'scanner-guard.http.secrets' => ['shop' => 'shop-secret'],
        'scanner-guard.ip_blocklist' => ['185.177.72.0/24'],
    ]);
    (new ScannerGuardServiceProvider(app()))->packageBooted();

    $timestamp = (string) now()->timestamp;
    $signature = $this->scannerGuard->sign($timestamp, 'shop', 'shop-secret');

    $response = $this->getJson('/scanner-guard/bans', ['X-Source' => 'shop', 'X-Timestamp' => $timestamp, 'X-Signature' => $signature])->assertOk();

    expect($response->headers->get('X-Signature'))->toBe($this->scannerGuard->signResponse(
        (string) $response->headers->get('X-Timestamp'), $signature, 'shop', $response->getContent(), 'shop-secret',
    ))->and($response->headers->get('Cache-Control'))->toContain('no-transform');
});

it('accepts a signed response', function (bool $required) {
    config(['scanner-guard.http.require_signed_response' => $required]);
    fakeSignedCentral(fn (Request $request) => signedHeaders($request));

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    expect($this->scannerGuard->isIpBlocked('185.177.72.69'))->toBeTrue();
})->with(['required' => true, 'optional' => false]);

it('refuses a bad signature even when signing is optional, keeping the last list', function (array $override) {
    $this->scannerGuard->applyDenylist(['bans' => [], 'ip_blocklist' => ['203.0.113.5']]);
    fakeSignedCentral(fn (Request $request) => signedHeaders($request, $override));

    $this->artisan('scanner-guard:pull-denylist')->assertFailed();

    expect($this->scannerGuard->isIpBlocked('185.177.72.69'))->toBeFalse()
        ->and($this->scannerGuard->isIpBlocked('203.0.113.5'))->toBeTrue();
})->with([
    'tampered body' => [['body' => '{"bans":[]}']],
    'wrong secret' => [['secret' => 'other']],
    'another source' => [['source' => 'blog']],
    'another request' => [['request' => str_repeat('0', 64)]],
    'expired' => fn () => ['timestamp' => (string) now()->subMinutes(10)->timestamp],
    'not a timestamp' => [['timestamp' => 'now']],
]);

it('does not take the request signature for a response signature', function () {
    fakeSignedCentral(fn (Request $request) => ['X-Timestamp' => $request->header('X-Timestamp')[0], 'X-Signature' => $request->header('X-Signature')[0]]);

    $this->artisan('scanner-guard:pull-denylist')->assertFailed();
});

it('accepts an unsigned response only until it is required', function () {
    fakeSignedCentral(fn () => []);
    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    config(['scanner-guard.http.require_signed_response' => true]);
    $this->artisan('scanner-guard:pull-denylist')->assertFailed();
});
