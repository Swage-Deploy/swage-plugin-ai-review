<?php

namespace Swage\AiReview\Review;

use App\Models\Server;
use Swage\AiReview\Models\IgnoredFinding;

/**
 * What the review is given about a server: what Swage knows about it, figures worked out from the snapshot, the
 * security scanner's records when it is installed, and the snapshot itself.
 */
class ReviewContext
{
    /**
     * The most of each service's config override sent, so a long one can't crowd out the rest of the review.
     */
    public const int MAX_OVERRIDE_BYTES = 2000;

    public function __construct(protected Capacity $capacity, protected SecurityScanner $scanner, protected NetworkExposure $exposure) {}

    /**
     * The data the review is given, as the JSON sent, which is stored with the review so people can see what it saw.
     *
     * @param  array<string, string>  $snapshot
     */
    public function encode(Server $server, array $snapshot): string
    {
        return json_encode($this->build($server, $snapshot), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    }

    /**
     * The prompt for the given data.
     */
    public static function wrap(string $json): string
    {
        return "Review this server. The data is JSON.\n\n".$json;
    }

    /**
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>
     */
    public function build(Server $server, array $snapshot): array
    {
        $machine = $this->machine($snapshot['machine'] ?? '');
        $inContainer = (bool) ($machine['shares_host_kernel'] ?? false);

        if ($inContainer && isset($snapshot['resources'])) {
            $snapshot['resources'] = $this->labelHostKernel($snapshot['resources']);
        }

        return [
            'reviewed_at' => now()->toIso8601String(),
            'server' => $this->server($server, $inContainer),
            'machine' => $machine,
            'capacity' => $this->capacity->for($server, $snapshot),
            'ssh_password_guesses' => $this->passwordGuesses($snapshot),
            'network_exposure' => $this->exposure->for($snapshot),
            'security_scanner' => $this->scanner->for($server),
            'ignored_findings' => IgnoredFinding::query()->where('server_id', $server->id)->orderBy('key')->get()
                ->map(fn (IgnoredFinding $finding): array => ['key' => $finding->key, 'title' => $finding->title])->all(),
            'snapshot' => collect(SnapshotScript::SECTIONS)
                ->mapWithKeys(fn (string $label, string $section): array => [$label => $snapshot[$section] ?? null])
                ->all(),
        ];
    }

    /**
     * What Swage knows about the server: its hardware, what runs on it, how Swage tuned it and what people changed.
     *
     * @return array<string, mixed>
     */
    protected function server(Server $server, bool $inContainer = false): array
    {
        return [
            'type' => $server->type->value,
            'specs' => $server->specs() ? [
                'cpu_cores' => $server->cpu_cores,
                'memory_mb' => $server->memory_mb,
                'disk_gb' => $server->disk_gb,
            ] : null,
            'php_versions' => $server->php_versions?->map->value->values()->all() ?? [],
            'default_php_version' => $server->default_php_version?->value,
            'mysql' => $server->usesMysql(),
            'postgres' => $server->usesPostgres(),
            'redis' => (bool) $server->has_redis,
            'sites' => $server->sites()->count(),
            'daemons' => $server->daemons()->count(),
            'swage_tuning' => $inContainer ? $this->withoutHostTuning($server->tuning) : $server->tuning,
            'config_overrides' => collect($server->config_overrides ?? [])
                ->filter(fn (mixed $override): bool => is_string($override) && trim($override) !== '')
                ->map(fn (string $override): string => mb_strcut($override, 0, self::MAX_OVERRIDE_BYTES))
                ->all(),
        ];
    }

    /**
     * A container can't change swap or kernel settings, which belong to its host, so Swage skips them when it tunes
     * one. What it would have set is left out, so the review doesn't hold the container to it.
     *
     * @param  array<string, mixed>|null  $tuning
     * @return array<string, mixed>|null
     */
    protected function withoutHostTuning(?array $tuning): ?array
    {
        if ($tuning === null) {
            return null;
        }

        unset($tuning['swap'], $tuning['kernel']);

        return [...$tuning, 'swap_and_kernel' => 'Not set by Swage: this server is a container, and its swap and kernel settings belong to the machine it runs on.'];
    }

    /**
     * Say that the kernel settings a container reports are its host's, which only the host can change.
     */
    protected function labelHostKernel(string $resources): string
    {
        return (string) preg_replace('/^((?:vm|fs|net|kernel)\.[\w.]+ = .*)$/m', '$1 (the host\'s, which this container can\'t change)', $resources);
    }

    /**
     * Whether the server is a virtual machine or a container, and the memory and CPU a container is limited to, which
     * can be less than its host has.
     *
     * @return array<string, mixed>|null
     */
    protected function machine(string $section): ?array
    {
        if (in_array(trim($section), ['', 'unavailable'], true)) {
            return null;
        }

        $values = collect(explode("\n", $section))
            ->map(fn (string $line): array => array_map(trim(...), explode(':', $line, 2)) + [1 => ''])
            ->mapWithKeys(fn (array $pair): array => [$pair[0] => $pair[1]]);

        $container = $values->get('container', 'none');
        $virtualization = $values->get('virtualization', 'none');
        $memory = $values->get('cgroup memory.max');
        $cpu = preg_split('/\s+/', (string) $values->get('cgroup cpu.max', ''));

        return [
            'kind' => match (true) {
                $container !== 'none' => 'container',
                $virtualization !== 'none' => 'virtual machine',
                default => 'physical machine',
            },
            'technology' => $container !== 'none' ? $container : ($virtualization !== 'none' ? $virtualization : null),
            'hardware' => $values->get('hardware'),
            'shares_host_kernel' => $container !== 'none',
            'memory_limit_mb' => is_numeric($memory) ? intdiv((int) $memory, 1024 * 1024) : null,
            'cpu_limit_cores' => is_numeric($cpu[0] ?? null) && is_numeric($cpu[1] ?? null) && (int) $cpu[1] > 0 ? round((int) $cpu[0] / (int) $cpu[1], 2) : null,
        ];
    }

    /**
     * Whether a failed SSH password guess could ever succeed, worked out from the snapshot rather than left to the
     * model, which tends to rate guessing as serious even when nothing it guesses can work.
     *
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>
     */
    protected function passwordGuesses(array $snapshot): array
    {
        $readable = fn (string $section): bool => ! in_array(trim($snapshot[$section] ?? ''), ['', 'unavailable'], true);

        if (! $readable('sshd') || ! $readable('accounts') || ! $readable('passwords')) {
            return ['can_succeed' => null, 'accounts_open_to_guessing' => [], 'why' => 'The SSH settings, accounts or passwords could not be read.'];
        }

        $settings = collect(explode("\n", $snapshot['sshd']))
            ->map(fn (string $line): array => preg_split('/\s+/', strtolower(trim($line)), 2) + [1 => ''])
            ->mapWithKeys(fn (array $setting): array => [$setting[0] => trim($setting[1])]);

        $methods = $settings->get('authenticationmethods', 'any');

        // A guess alone only gets in when one of the allowed ways of logging in needs nothing but a password.
        $passwordsAccepted = ($settings->get('passwordauthentication') === 'yes' || $settings->get('kbdinteractiveauthentication') === 'yes')
            && ($methods === 'any' || collect(preg_split('/\s+/', $methods))->contains(
                fn (string $list): bool => collect(explode(',', $list))->every(fn (string $method): bool => in_array(strtok($method, ':'), ['password', 'keyboard-interactive'], true)),
            ));

        if (! $passwordsAccepted) {
            return ['can_succeed' => false, 'accounts_open_to_guessing' => [], 'why' => 'SSH does not accept password logins.'];
        }

        $canLogIn = collect(explode("\n", $snapshot['accounts']))->map(fn (string $line): string => strtok(trim($line), ' ') ?: '')->filter()->all();

        $open = collect(explode("\n", $snapshot['passwords']))
            ->map(fn (string $line): array => explode(' ', trim($line), 2) + [1 => ''])
            ->filter(fn (array $account): bool => in_array($account[0], $canLogIn, true)
                && ($account[1] === 'password set' || ($account[1] === 'empty password' && $settings->get('permitemptypasswords') === 'yes'))
                && ($account[0] !== 'root' || $settings->get('permitrootlogin') === 'yes'))
            ->map(fn (array $account): string => $account[0])
            ->values()
            ->all();

        return $open === []
            ? ['can_succeed' => false, 'accounts_open_to_guessing' => [], 'why' => 'SSH accepts passwords, but no account that may log in with one has a usable password.']
            : ['can_succeed' => true, 'accounts_open_to_guessing' => $open, 'why' => 'SSH accepts passwords, and these accounts can log in with one.'];
    }
}
