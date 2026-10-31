<?php

namespace Swage\AiReview\Jobs;

use App\Models\User;
use App\Ssh\RemoteShell;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use RuntimeException;
use Swage\AiReview\AiSettings;
use Swage\AiReview\Category;
use Swage\AiReview\Models\IgnoredFinding;
use Swage\AiReview\Models\Review;
use Swage\AiReview\Models\ReviewState;
use Swage\AiReview\Review\ReviewContext;
use Swage\AiReview\Review\SecurityScanner;
use Swage\AiReview\Review\ServerReviewer;
use Swage\AiReview\Review\SnapshotScript;
use Swage\AiReview\Severity;
use Throwable;

/**
 * Asks the AI model to review a server. The only thing it runs on the server is the read-only snapshot script, which
 * the AI has no say in, and the only thing it writes is the review, to Swage's database. Reviews are not recorded in
 * the server's activity log, since they change nothing.
 */
class ReviewServer implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    /**
     * How long, in seconds, the snapshot script may take.
     */
    public const int SNAPSHOT_TIMEOUT = 90;

    public int $timeout;

    public int $tries = 1;

    public function __construct(public ReviewState $state, public ?User $requestedBy = null)
    {
        // Long enough to read the server and wait for the API.
        $this->timeout = (int) config('ai-review.timeout') + self::SNAPSHOT_TIMEOUT + 30;
    }

    /**
     * Only one review of a server may be queued at a time.
     */
    public function uniqueId(): string
    {
        return (string) $this->state->server_id;
    }

    /**
     * Execute the job. A review that fails still counts as the server's latest, so a broken API isn't asked again
     * until the next review is due.
     */
    public function handle(RemoteShell $shell, AiSettings $settings, ReviewContext $context, SecurityScanner $scanner): void
    {
        if (! $this->state->enabled || ! $settings->isConfigured()) {
            return;
        }

        $server = $this->state->server;

        try {
            $snapshot = $this->snapshot($shell);
            $input = $context->encode($server, $snapshot);

            $response = (new ServerReviewer($scanner->instructions()))->prompt(
                ReviewContext::wrap($input),
                provider: $settings->provider(),
                model: $settings->model(),
                timeout: (int) config('ai-review.timeout'),
            );

            $reply = $this->reply($response->structured, $response->text);

            Review::create([
                'server_id' => $server->id,
                'model' => (string) $settings->model(),
                'reported_model' => $response->meta->model,
                'summary' => mb_strimwidth(trim((string) ($reply['summary'] ?? '')), 0, 2000, '…'),
                'findings' => $this->findings($reply['findings'] ?? []),
                'checked' => $this->checked($reply['checked'] ?? []),
                'missing_sections' => SnapshotScript::missing($snapshot),
                'input' => $input,
                'input_tokens' => $response->usage->inputTokens ?: null,
                'output_tokens' => $response->usage->outputTokens ?: null,
                'requested_by_id' => $this->requestedBy?->id,
            ]);

            $this->state->update(['reviewed_at' => now(), 'error' => null]);
        } catch (Throwable $exception) {
            $message = $server->redactSecrets($exception->getMessage());

            if (filled($key = $settings->apiKey())) {
                $message = str_replace($key, '********', $message);
            }

            $this->state->update(['reviewed_at' => now(), 'error' => mb_strimwidth($message, 0, 1000, '…')]);
        }
    }

    /**
     * Read the server.
     *
     * @return array<string, string>
     *
     * @throws RuntimeException when the server cannot be read.
     */
    protected function snapshot(RemoteShell $shell): array
    {
        $script = SnapshotScript::make($this->state->server);
        $result = $shell->run($this->state->server, $script->render(), timeout: self::SNAPSHOT_TIMEOUT);

        if ($result->failed()) {
            throw new RuntimeException(trim("Reading the server failed with exit code {$result->exitCode}. ".mb_strimwidth($this->state->server->redactSecrets($result->output), 0, 500, '…')));
        }

        return $script->parse($result->output);
    }

    /**
     * The model's answer. Some APIs, such as Ollama's, ignore the requested format, so when Laravel AI couldn't read
     * the reply this reads the JSON object in it, allowing for text around it and raw line breaks in its strings.
     *
     * @param  array<string, mixed>  $structured
     * @return array<string, mixed>
     *
     * @throws RuntimeException when the reply has no answer in it.
     */
    protected function reply(array $structured, string $text): array
    {
        if (filled($structured['summary'] ?? null)) {
            return $structured;
        }

        $start = strpos($text, '{');
        $end = strrpos($text, '}');

        if ($start !== false && $end > $start) {
            $json = substr($text, $start, $end - $start + 1);
            $decoded = json_decode($json, true) ?? json_decode((string) preg_replace('/[\x00-\x1F]/', ' ', $json), true);

            if (is_array($decoded) && filled($decoded['summary'] ?? null)) {
                return $decoded;
            }
        }

        $text = trim($text);
        $excerpt = mb_strlen($text) > 600 ? mb_substr($text, 0, 300).' … '.mb_substr($text, -300) : $text;

        throw new RuntimeException("The model's reply wasn't the JSON the review asks for, so it couldn't be read. Try Review now, or a model that follows instructions more closely. The reply was: ".($excerpt === '' ? '(empty)' : $excerpt));
    }

    /**
     * Keep the entries of what the review checked that say what was seen, cut to a sensible length.
     *
     * @return list<array{area: string, observation: string}>
     */
    protected function checked(mixed $checked): array
    {
        return collect(is_array($checked) ? $checked : [])
            ->filter(fn (mixed $entry): bool => is_array($entry) && filled($entry['area'] ?? null) && filled($entry['observation'] ?? null))
            ->take(ServerReviewer::MAX_CHECKED)
            ->map(fn (array $entry): array => [
                'area' => mb_strimwidth(trim((string) $entry['area']), 0, 120, '…'),
                'observation' => mb_strimwidth(trim((string) $entry['observation']), 0, 500, '…'),
            ])
            ->values()
            ->all();
    }

    /**
     * Keep the findings that have what the panel shows, cut to a sensible length.
     *
     * @return list<array{key: string, category: string, severity: string, title: string, detail: string, suggestion: string}>
     */
    protected function findings(mixed $findings): array
    {
        return collect(is_array($findings) ? $findings : [])
            ->filter(fn (mixed $finding): bool => is_array($finding) && filled($finding['title'] ?? null))
            ->take(ServerReviewer::MAX_FINDINGS)
            ->map(fn (array $finding): array => [
                'key' => IgnoredFinding::keyFor($finding),
                'category' => (Category::tryFrom((string) ($finding['category'] ?? '')) ?? Category::Reliability)->value,
                'severity' => (Severity::tryFrom((string) ($finding['severity'] ?? '')) ?? Severity::Low)->value,
                'title' => mb_strimwidth(trim((string) $finding['title']), 0, 200, '…'),
                'detail' => mb_strimwidth(trim((string) ($finding['detail'] ?? '')), 0, 2000, '…'),
                'suggestion' => mb_strimwidth(trim((string) ($finding['suggestion'] ?? '')), 0, 2000, '…'),
            ])
            ->values()
            ->all();
    }
}
