@php
    $canManage = auth()->user()->can('update', $server);
@endphp

<div class="flex flex-col gap-6" @if ($enabled) wire:poll.15s @endif>
    <x-panel icon="sparkles" :heading="__('AI review')" :description="__('An AI model reads a read-only snapshot of this server, covering its setup, resources and service logs, and suggests what to fix in its security, performance and reliability. It can\'t change anything: its suggestions are only shown here for you to act on.')">
        @if ($enabled && $canManage && $this->ai->isConfigured())
            <x-slot:actions>
                <flux:button size="sm" variant="ghost" icon="arrow-path" wire:click="review">{{ __('Review now') }}</flux:button>
            </x-slot:actions>
        @endif

        <div class="flex flex-col gap-6">
            @if (! $this->ai->isConfigured())
                <flux:callout icon="cog-6-tooth" color="zinc">
                    <flux:callout.text>{{ __('Set the OpenAI compatible API to use, and its model, on the plugin\'s config page first.') }}</flux:callout.text>
                    @can('administer')
                        <x-slot:actions>
                            <flux:button size="sm" icon="cog-6-tooth" :href="route('plugins.configure', ['server', 'ai-review'])" wire:navigate>{{ __('Configure') }}</flux:button>
                        </x-slot:actions>
                    @endcan
                </flux:callout>
            @endif

            @if ($this->ai->isConfigured() || $enabled)
                <flux:switch wire:model.live="enabled" :label="__('Review this server with AI')" align="left" :disabled="! $canManage || ! $this->ai->isConfigured()"
                    :description="__('Every :hours hours. The server\'s hardware and Swage\'s tuning, a snapshot of its SSH settings, open ports, firewall, updates, accounts, memory, disks, PHP-FPM, nginx, database and Redis settings and figures, and summaries of their logs and the system journal, are sent to :host, with the security scanner\'s records if it scans this server.', ['hours' => config('ai-review.interval_hours'), 'host' => $this->ai->host() ?? __('the configured API')])" />
                <flux:error name="enabled" />
            @endif

            @if ($this->state->error)
                <flux:callout icon="exclamation-triangle" color="red">
                    <flux:callout.heading>{{ __('The last review failed') }}</flux:callout.heading>
                    <flux:callout.text class="font-mono text-xs">{{ $this->state->error }}</flux:callout.text>
                </flux:callout>
            @endif

            @if ($review = $this->latestReview)
                <div class="flex flex-col gap-1">
                    <flux:text class="text-zinc-800 dark:text-zinc-200">{{ $review->summary }}</flux:text>
                    <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <flux:text class="text-xs">
                            {{ __('Reviewed :time by :model.', ['time' => $review->created_at->diffForHumans(), 'model' => $review->reported_model && $review->reported_model !== $review->model ? "{$review->model} ({$review->reported_model})" : $review->model]) }}
                            @if ($review->input_tokens)
                                {{ __('Read :input tokens and wrote :output.', ['input' => number_format($review->input_tokens), 'output' => number_format((int) $review->output_tokens)]) }}
                            @endif
                        </flux:text>
                        @if ($canManage)
                            <flux:button size="xs" variant="ghost" icon="document-magnifying-glass" wire:click="showReviewInput">{{ __('What was sent') }}</flux:button>
                        @endif
                    </div>
                </div>

                @if ($review->missingLabels() !== [])
                    <flux:callout icon="exclamation-triangle" color="amber">
                        <flux:callout.heading>{{ __('Parts of the server couldn\'t be read') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('The review didn\'t see: :parts. A command failed, so anything wrong there wasn\'t checked.', ['parts' => implode(', ', $review->missingLabels())]) }}</flux:callout.text>
                    </flux:callout>
                @endif

                @php
                    $ignoredKeys = $this->ignoredFindings->pluck('key')->all();
                    [$ignoredNow, $findings] = collect($review->sortedFindings())->partition(fn ($finding) => in_array($finding['key'], $ignoredKeys, true));
                @endphp

                @if ($findings->isEmpty())
                    <flux:text>{{ $ignoredNow->isEmpty() ? __('Nothing needs attention.') : __('Nothing needs attention apart from what\'s ignored.') }}</flux:text>
                @else
                    <div class="flex flex-col divide-y divide-zinc-200 rounded-lg border border-zinc-200 dark:divide-white/8 dark:border-white/8">
                        @foreach ($findings as $finding)
                            <div class="flex flex-col gap-3 p-4" wire:key="finding-{{ $review->id }}-{{ $finding['key'] }}">
                                <div class="flex flex-wrap items-center gap-2">
                                    <flux:badge size="sm" :color="$finding['severity']->color()">{{ $finding['severity']->label() }}</flux:badge>
                                    <flux:badge size="sm" color="zinc" variant="outline" :icon="$finding['category']->icon()">{{ $finding['category']->label() }}</flux:badge>
                                    <span class="font-medium text-zinc-900 dark:text-white">{{ $finding['title'] }}</span>
                                    @if ($canManage)
                                        <flux:button size="xs" variant="ghost" icon="eye-slash" class="ms-auto" wire:click="ignoreFinding('{{ $finding['key'] }}')">{{ __('Ignore') }}</flux:button>
                                    @endif
                                </div>
                                <flux:text class="whitespace-pre-line">{{ $finding['detail'] }}</flux:text>
                                @if (filled($finding['suggestion']))
                                    <details class="group" wire:key="suggestion-{{ $review->id }}-{{ $finding['key'] }}" wire:ignore.self>
                                        <summary class="flex w-fit cursor-pointer list-none items-center gap-1 text-xs font-medium text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 [&::-webkit-details-marker]:hidden">
                                            <flux:icon.chevron-right variant="micro" class="transition-transform group-open:rotate-90" />
                                            {{ __('Suggestion') }}
                                        </summary>
                                        <div class="mt-2 rounded-md bg-zinc-50 p-3 dark:bg-white/5">
                                            <flux:text class="whitespace-pre-line break-words">{{ $finding['suggestion'] }}</flux:text>
                                        </div>
                                    </details>
                                @endif
                            </div>
                        @endforeach
                    </div>
                    <flux:text class="text-xs">{{ __('Suggestions come from an AI model and can be wrong. Check them before acting, and don\'t run a command you don\'t understand. Swage never runs them.') }}</flux:text>
                @endif

                @if ($this->ignoredFindings->isNotEmpty())
                    <div>
                        <flux:text class="text-xs font-medium uppercase tracking-wide">{{ __('Ignored') }}</flux:text>
                        <flux:text class="mt-1 text-xs">{{ __('Reviews still check for these, but they aren\'t listed with the findings to act on.') }}</flux:text>
                        <div class="mt-2 flex flex-col divide-y divide-zinc-200 rounded-lg border border-zinc-200 dark:divide-white/8 dark:border-white/8">
                            @foreach ($this->ignoredFindings as $ignored)
                                @php($current = $ignoredNow->firstWhere('key', $ignored->key))
                                <div class="flex flex-col gap-1 px-4 py-3" wire:key="ignored-{{ $ignored->id }}">
                                    <div class="flex items-center gap-2">
                                        @if ($current)
                                            <flux:badge size="sm" :color="$current['severity']->color()">{{ $current['severity']->label() }}</flux:badge>
                                        @endif
                                        <span class="text-sm font-medium text-zinc-800 dark:text-zinc-200">{{ $current['title'] ?? $ignored->title }}</span>
                                        @if ($canManage)
                                            <flux:button size="xs" variant="ghost" icon="eye" class="ms-auto" wire:click="stopIgnoring({{ $ignored->id }})">{{ __('Stop ignoring') }}</flux:button>
                                        @endif
                                    </div>
                                    <flux:text class="text-xs">
                                        {{ $current ? __('Still reported by the latest review.') : __('Not reported by the latest review.') }}
                                        {{ $ignored->ignoredBy ? __('Ignored by :name :time.', ['name' => $ignored->ignoredBy->name, 'time' => $ignored->created_at->diffForHumans()]) : __('Ignored :time.', ['time' => $ignored->created_at->diffForHumans()]) }}
                                    </flux:text>
                                    @if ($current)
                                        <details class="group text-sm" wire:key="ignored-said-{{ $ignored->id }}" wire:ignore.self>
                                            <summary class="flex w-fit cursor-pointer list-none items-center gap-1 text-xs font-medium text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 [&::-webkit-details-marker]:hidden">
                                                <flux:icon.chevron-right variant="micro" class="transition-transform group-open:rotate-90" />
                                                {{ __('What the review said') }}
                                            </summary>
                                            <flux:text class="mt-2 whitespace-pre-line">{{ $current['detail'] }}</flux:text>
                                            @if (filled($current['suggestion']))
                                                <flux:text class="mt-2 whitespace-pre-line break-words">{{ $current['suggestion'] }}</flux:text>
                                            @endif
                                        </details>
                                    @endif
                                </div>
                            @endforeach
                        </div>
                    </div>
                @endif

                @if (filled($review->checked))
                    <details class="group rounded-lg border border-zinc-200 dark:border-white/8" wire:key="checked-{{ $review->id }}" wire:ignore.self>
                        <summary class="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium text-zinc-800 dark:text-zinc-200 [&::-webkit-details-marker]:hidden">
                            <flux:icon.chevron-right variant="micro" class="text-zinc-400 transition-transform group-open:rotate-90" />
                            {{ __('What was checked') }}
                            <flux:badge size="sm" color="zinc">{{ count($review->checked) }}</flux:badge>
                        </summary>
                        <dl class="grid gap-x-6 gap-y-3 border-t border-zinc-200 px-4 py-4 text-sm sm:grid-cols-[minmax(0,12rem)_1fr] dark:border-white/8">
                            @foreach ($review->checked as $entry)
                                <dt class="font-medium text-zinc-800 dark:text-zinc-200" wire:key="checked-{{ $review->id }}-{{ $loop->index }}">{{ $entry['area'] }}</dt>
                                <dd class="-mt-2 text-zinc-600 sm:mt-0 dark:text-zinc-400">{{ $entry['observation'] }}</dd>
                            @endforeach
                        </dl>
                    </details>
                @else
                    <flux:callout icon="question-mark-circle" color="amber">
                        <flux:callout.text>{{ __('The model didn\'t say what it checked, so there\'s no sign it read the server. Try Review now, or a model that follows instructions more closely.') }}</flux:callout.text>
                    </flux:callout>
                @endif
            @elseif ($enabled)
                <flux:text>{{ __('Waiting for the first review.') }}</flux:text>
            @endif
        </div>
    </x-panel>

    <flux:modal name="ai-review-input" class="w-full max-w-4xl">
        <div class="flex flex-col gap-4">
            <div>
                <flux:heading size="lg">{{ __('What the review was sent') }}</flux:heading>
                <flux:text class="mt-1">{{ __('Everything the AI model was given for the latest review, exactly as it was sent, after its instructions.') }}</flux:text>
            </div>
            <pre class="max-h-[60vh] overflow-auto rounded-lg bg-zinc-50 p-4 font-mono text-xs whitespace-pre-wrap break-words text-zinc-800 dark:bg-white/5 dark:text-zinc-200">{{ $reviewInput }}</pre>
        </div>
    </flux:modal>
</div>
