<?php

namespace Swage\AiReview;

use App\Models\Server;
use App\Plugins\Attention;
use App\Plugins\HasAttention;
use App\Plugins\HasPluginSettings;
use App\Plugins\HasPluginTab;
use App\Servers\ServerIntegration;
use App\SourceControl\Setting;
use Illuminate\Database\Eloquent\Collection;

class AiReviewIntegration implements HasAttention, HasPluginSettings, HasPluginTab, ServerIntegration
{
    public function id(): string
    {
        return 'ai-review';
    }

    public function settingsComponent(): string
    {
        return 'ai-review.panel';
    }

    public function tabLabel(): string
    {
        return __('AI review');
    }

    public function tabIcon(): string
    {
        return 'sparkles';
    }

    /**
     * The API key is the only secret the plugin stores. It is never sent to servers.
     */
    public function secrets(Server $server): array
    {
        return array_values(array_filter([app(AiSettings::class)->apiKey()]));
    }

    public function settings(): array
    {
        return [
            new Setting('url', __('API URL'), __('The base URL of an OpenAI compatible API, ending before /chat/completions.'), Setting::URL, placeholder: 'https://api.openai.com/v1'),
            new Setting('api_key', __('API key'), __('Sent as a bearer token. Leave it blank for APIs that don\'t need one, such as a local Ollama.'), Setting::SECRET, required: false),
            new Setting('model', __('Model'), __('The model that reviews servers. It must support structured output (JSON schema responses).'), placeholder: 'gpt-4.1'),
        ];
    }

    public function settingsDescription(): string
    {
        return __('Reviews send a read-only snapshot of a server, covering its setup, resources and service logs, with what Swage knows about it and the security scanner\'s records, to this API, and show the findings and suggestions it sends back. They never change a server: nothing they suggest is run. Turn reviews on per server from the server\'s AI review tab.');
    }

    /**
     * Badge servers whose latest review has findings nobody has ignored.
     */
    public function attention(Collection $servers): array
    {
        return array_map(fn (array $item): Attention => new Attention(
            $item['count'],
            $item['severity']->value,
            trans_choice('AI review: :count finding|AI review: :count findings', $item['count']),
        ), app(NeedsAttention::class)->for($servers));
    }
}
