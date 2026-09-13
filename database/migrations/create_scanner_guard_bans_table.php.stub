<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('scanner-guard.table', 'scanner_guard_bans');

        Schema::create($table, function (Blueprint $table) {
            $table->id();
            $table->string('ip_hash', 64)->index();
            $table->string('reason', 30);
            $table->string('matched_value');
            $table->unsignedInteger('hit_count')->default(1);
            $table->timestamp('banned_at');
            $table->timestamp('expires_at')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('scanner-guard.table', 'scanner_guard_bans'));
    }
};
