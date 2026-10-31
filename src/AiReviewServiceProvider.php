<?php

namespace Swage\AiReview;

use App\Servers\ServerIntegrations;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use Swage\AiReview\Console\ReviewCommand;
use Swage\AiReview\Livewire\ReviewPanel;
use Swage\AiReview\Models\Review;

class AiReviewServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ai-review.php', 'ai-review');
    }

    /**
     * Register the integration and its panel, and check hourly for servers due a review. Swage's own daily pruning
     * only looks in its app/Models directory, so the plugin prunes old reviews itself.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'ai-review');

        Livewire::component('ai-review.panel', ReviewPanel::class);

        $this->app->make(ServerIntegrations::class)->register(AiReviewIntegration::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ReviewCommand::class]);
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $schedule->command('ai-review:review')->hourly()->withoutOverlapping();
            $schedule->command('model:prune', ['--model' => [Review::class]])->daily();
        });
    }
}
