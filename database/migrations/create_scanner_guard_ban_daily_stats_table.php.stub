<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('scanner-guard.daily_stats_table', 'scanner_guard_ban_daily_stats');

        Schema::create($table, function (Blueprint $table) {
            $table->id();
            $table->date('date')->unique();

            $table->unsignedBigInteger('bans_count')->default(0);
            $table->unsignedBigInteger('hits_total')->default(0);

            $table->json('reason_stats')->nullable();
            $table->json('top_matched_values')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('scanner-guard.daily_stats_table', 'scanner_guard_ban_daily_stats'));
    }
};
