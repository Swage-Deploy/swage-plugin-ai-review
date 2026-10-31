<?php

namespace Swage\AiReview;

use App\Plugins\PluginSettings;
use Laravel\Ai\Ai;

/**
 * The OpenAI compatible API reviews use, as entered on the plugin's config page.
 */
class AiSettings
{
    /**
     * The name the API is registered under with Laravel AI.
     */
    public const string PROVIDER = 'ai-review';

    public function isConfigured(): bool
    {
        return filled($this->url()) && filled($this->model());
    }

    public function url(): ?string
    {
        return $this->get('url');
    }

    public function apiKey(): ?string
    {
        return $this->get('api_key');
    }

    public function model(): ?string
    {
        return $this->get('model');
    }

    /**
     * The host of the API, for telling people where reviews are sent.
     */
    public function host(): ?string
    {
        return parse_url((string) $this->url(), PHP_URL_HOST) ?: null;
    }

    /**
     * Register the API with Laravel AI from the saved settings, returning the name to prompt it by.
     */
    public function provider(): string
    {
        Ai::build([
            'name' => self::PROVIDER,
            'driver' => 'openai-compatible',
            'url' => $this->url(),
            'key' => $this->apiKey(),
            'models' => ['text' => ['default' => $this->model()]],
        ]);

        return self::PROVIDER;
    }

    protected function get(string $key): ?string
    {
        return app(PluginSettings::class)->get(app(AiReviewIntegration::class), $key);
    }
}
