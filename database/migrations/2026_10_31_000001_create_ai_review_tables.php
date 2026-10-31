<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Whether each server is reviewed, its reviews, with what each was sent and checked, and the findings people have
     * chosen to ignore on it.
     */
    public function up(): void
    {
        Schema::create('ai_review_states', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->unique()->constrained()->cascadeOnDelete();
            $table->boolean('enabled')->default(false);
            $table->timestamp('reviewed_at')->nullable();
            $table->text('error')->nullable();
            $table->timestamps();
        });

        Schema::create('ai_review_reviews', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('model');
            $table->string('reported_model')->nullable();
            $table->text('summary');
            $table->json('findings');
            $table->json('checked')->nullable();
            $table->json('missing_sections')->nullable();
            $table->longText('input')->nullable();
            $table->unsignedInteger('input_tokens')->nullable();
            $table->unsignedInteger('output_tokens')->nullable();
            $table->foreignId('requested_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['server_id', 'created_at']);
        });

        Schema::create('ai_review_ignored_findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('key', 80);
            $table->string('title');
            $table->foreignId('ignored_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->unique(['server_id', 'key']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ai_review_ignored_findings');
        Schema::dropIfExists('ai_review_reviews');
        Schema::dropIfExists('ai_review_states');
    }
};
