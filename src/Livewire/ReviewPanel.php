<?php

namespace Swage\AiReview\Livewire;

use App\Models\Server;
use Flux\Flux;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Validation\ValidationException;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Swage\AiReview\AiSettings;
use Swage\AiReview\Jobs\ReviewServer;
use Swage\AiReview\Models\IgnoredFinding;
use Swage\AiReview\Models\Review;
use Swage\AiReview\Models\ReviewState;

/**
 * The AI review's panel on a server's Plugins tab: whether the server is reviewed, the latest review's findings, the
 * findings people have ignored, and what the review checked and was sent.
 */
class ReviewPanel extends Component
{
    public Server $server;

    public bool $enabled = false;

    /**
     * The data the latest review was sent, while it is being viewed.
     */
    #[Locked]
    public ?string $reviewInput = null;

    public function mount(): void
    {
        $this->authorize('view', $this->server);

        $this->enabled = $this->state->enabled;
    }

    #[Computed]
    public function state(): ReviewState
    {
        return ReviewState::for($this->server);
    }

    #[Computed]
    public function ai(): AiSettings
    {
        return app(AiSettings::class);
    }

    /**
     * Turn reviews on or off for the server. Turning them on reviews the server straight away.
     *
     * @throws ValidationException
     */
    public function updatedEnabled(): void
    {
        $this->authorize('update', $this->server);

        if ($this->enabled && ! $this->ai->isConfigured()) {
            $this->enabled = false;

            throw ValidationException::withMessages(['enabled' => __('An administrator needs to set the AI review\'s API URL and model first.')]);
        }

        $this->state->update(['enabled' => $this->enabled]);

        if ($this->enabled) {
            ReviewServer::dispatch($this->state, auth()->user());
        }

        Flux::toast(variant: 'success', text: $this->enabled
            ? __('Reviewing this server with AI. The first review shows here in a minute or two.')
            : __('Stopped reviewing this server with AI. Earlier reviews are kept.'));
    }

    public function review(): void
    {
        $this->authorize('update', $this->server);

        abort_unless($this->state->enabled && $this->ai->isConfigured(), 403);

        ReviewServer::dispatch($this->state, auth()->user());

        Flux::toast(variant: 'success', text: __('Reviewing this server with AI.'));
    }

    /**
     * The latest review, without the data it was sent, which is only loaded when someone asks to see it.
     */
    #[Computed]
    public function latestReview(): ?Review
    {
        return Review::query()->where('server_id', $this->server->id)->latest()->latest('id')
            ->first(['id', 'server_id', 'model', 'reported_model', 'summary', 'findings', 'checked', 'missing_sections', 'input_tokens', 'output_tokens', 'requested_by_id', 'created_at']);
    }

    /**
     * Show the data the latest review was sent. It includes the server's accounts, sudo rules and service settings, so
     * only people who can manage the server see it.
     */
    public function showReviewInput(): void
    {
        $this->authorize('update', $this->server);

        $this->reviewInput = $this->latestReview
            ? (string) Review::query()->whereKey($this->latestReview->id)->value('input')
            : null;

        Flux::modal('ai-review-input')->show();
    }

    /**
     * The findings people have ignored on the server, newest first.
     *
     * @return Collection<int, IgnoredFinding>
     */
    #[Computed]
    public function ignoredFindings(): Collection
    {
        return IgnoredFinding::query()->where('server_id', $this->server->id)->with('ignoredBy')->latest()->latest('id')->get();
    }

    /**
     * Ignore one of the latest review's findings. Later reviews still check for it, and it shows under Ignored.
     */
    public function ignoreFinding(string $key): void
    {
        $this->authorize('update', $this->server);

        $finding = collect($this->latestReview?->sortedFindings() ?? [])->firstWhere('key', $key);

        abort_if($finding === null, 404);

        IgnoredFinding::firstOrCreate(
            ['server_id' => $this->server->id, 'key' => $key],
            ['title' => mb_strimwidth($finding['title'], 0, 255, '…'), 'ignored_by_id' => auth()->id()],
        );

        unset($this->ignoredFindings);

        Flux::toast(variant: 'success', text: __('Ignoring ":title". Reviews still check for it, and it shows under Ignored.', ['title' => $finding['title']]));
    }

    public function stopIgnoring(int $ignoredId): void
    {
        $this->authorize('update', $this->server);

        IgnoredFinding::query()->where('server_id', $this->server->id)->findOrFail($ignoredId)->delete();

        unset($this->ignoredFindings);
    }

    public function render(): View
    {
        return view('ai-review::panel');
    }
}
