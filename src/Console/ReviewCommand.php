<?php

namespace Swage\AiReview\Console;

use App\Enums\ServerStatus;
use Illuminate\Console\Command;
use Swage\AiReview\AiSettings;
use Swage\AiReview\Jobs\ReviewServer;
use Swage\AiReview\Models\ReviewState;

class ReviewCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'ai-review:review';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Ask the AI model to review the servers it is turned on for that are due a review';

    /**
     * Execute the console command.
     */
    public function handle(AiSettings $settings): int
    {
        if (! $settings->isConfigured()) {
            $this->components->info('The AI review is not configured.');

            return self::SUCCESS;
        }

        $due = now()->subHours(max(1, (int) config('ai-review.interval_hours')));

        $states = ReviewState::query()
            ->where('enabled', true)
            ->where(fn ($query) => $query->whereNull('reviewed_at')->orWhere('reviewed_at', '<=', $due))
            ->whereHas('server', fn ($query) => $query->where('status', ServerStatus::Active))
            ->with('server')
            ->get();

        $states->each(fn (ReviewState $state) => ReviewServer::dispatch($state));

        $this->components->info("Reviewing {$states->count()} server(s).");

        return self::SUCCESS;
    }
}
