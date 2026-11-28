<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * One IP asked of several agents at once (ScannerGuard::requestDiagnosis()):
 * each server answers in its own ScannerGuardAgentDiagnosis.
 *
 * @property int $id
 * @property string $ip
 * @property int $capture seconds of tcpdump, 0 = none
 * @property string|null $requested_by who asked, as their name read then
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 * @property-read Collection<int, ScannerGuardAgentDiagnosis> $diagnoses
 */
class ScannerGuardDiagnosisRequest extends Model
{
    protected $table = 'scanner_guard_diagnosis_requests';

    protected $fillable = [
        'ip',
        'capture',
        'requested_by',
    ];

    protected function casts(): array
    {
        return [
            'ip' => 'encrypted',
            'capture' => 'integer',
        ];
    }

    /**
     * @return HasMany<ScannerGuardAgentDiagnosis, $this>
     */
    public function diagnoses(): HasMany
    {
        return $this->hasMany(ScannerGuardAgentDiagnosis::class, 'request_id');
    }
}
