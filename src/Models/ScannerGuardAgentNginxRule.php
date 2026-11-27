<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An optional nginx rule of scanner-guard-agent (2.8.0+), turned on for every
 * agent but the sources in except. Only the name goes to the agents: the rule
 * itself ships with the agent, so the central app never writes nginx config.
 *
 * @property int $id
 * @property string $name
 * @property bool $enabled
 * @property list<string>|null $except
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardAgentNginxRule extends Model
{
    /** The optional rules the agent knows, with what each one blocks. */
    public const NAMES = [
        'cms' => 'WordPress, Joomla and phpMyAdmin paths (wp-login.php, xmlrpc.php, /administrator/, /phpmyadmin). Only for servers without them.',
        'rfi' => 'A full URL in a parameter (remote file inclusion). Also matches redirect and callback URLs.',
        'encoded' => 'A percent-encoded letter (%55NION). Browsers don\'t send these, some API clients do.',
        'empty-agent' => 'No User-Agent at all. Also blocks some monitors and webhooks.',
    ];

    protected $table = 'scanner_guard_agent_nginx_rules';

    protected $fillable = [
        'name',
        'enabled',
        'except',
    ];

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'except' => 'array',
        ];
    }

    public function appliesTo(?string $source): bool
    {
        return $this->enabled
            && array_key_exists($this->name, static::NAMES)
            && ! in_array($source, (array) $this->except, true);
    }
}
