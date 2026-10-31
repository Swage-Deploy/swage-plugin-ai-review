<?php

namespace Swage\AiReview\Review;

use App\Models\Server;
use App\Provisioning\ServerTuner;

/**
 * Figures worked out from the snapshot and Swage's tuning, such as how many PHP workers fit in memory at the size they
 * really are. Models get this arithmetic wrong often enough that it is done here and handed to them.
 */
class Capacity
{
    /**
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>
     */
    public function for(Server $server, array $snapshot): array
    {
        return [
            'memory' => $this->memory($snapshot['resources'] ?? ''),
            'load' => $this->load($snapshot['resources'] ?? ''),
            'fullest_disk' => $this->disk($snapshot['disk'] ?? ''),
            'php_workers' => $this->phpWorkers($server, $snapshot['php-fpm'] ?? ''),
        ];
    }

    /**
     * @return array<string, int|float>|null
     */
    protected function memory(string $resources): ?array
    {
        if (! preg_match('/^Mem:\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+)/m', $resources, $memory)) {
            return null;
        }

        preg_match('/^Swap:\s+(\d+)\s+(\d+)/m', $resources, $swap);

        return [
            'total_mb' => (int) $memory[1],
            'available_mb' => (int) $memory[3],
            'available_percent' => $memory[1] > 0 ? round($memory[3] / $memory[1] * 100, 1) : 0,
            'swap_total_mb' => (int) ($swap[1] ?? 0),
            'swap_used_mb' => (int) ($swap[2] ?? 0),
        ];
    }

    /**
     * @return array<string, int|float>|null
     */
    protected function load(string $resources): ?array
    {
        if (! preg_match('/^cpu cores: (\d+)/m', $resources, $cores) || ! preg_match('/^load average: ([\d.]+) ([\d.]+) ([\d.]+)/m', $resources, $load) || (int) $cores[1] < 1) {
            return null;
        }

        return [
            'cpu_cores' => (int) $cores[1],
            'per_core_1_minute' => round((float) $load[1] / (int) $cores[1], 2),
            'per_core_15_minutes' => round((float) $load[3] / (int) $cores[1], 2),
        ];
    }

    /**
     * @return array{mount: string, used_percent: int}|null
     */
    protected function disk(string $disk): ?array
    {
        preg_match_all('/^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(\/\S*)$/m', strstr($disk, "\n-- ", true) ?: $disk, $matches, PREG_SET_ORDER);

        $fullest = collect($matches)->sortByDesc(fn (array $match): int => (int) $match[1])->first();

        return $fullest ? ['mount' => $fullest[2], 'used_percent' => (int) $fullest[1]] : null;
    }

    /**
     * How big PHP-FPM's workers really are, against what Swage assumed when it sized the pools, and how many fit in
     * the memory Swage set aside for PHP.
     *
     * @return array<string, mixed>|null
     */
    protected function phpWorkers(Server $server, string $phpFpm): ?array
    {
        preg_match_all('/^(\S+): (\d+) processes, average (\d+) MB, largest (\d+) MB$/m', $phpFpm, $matches, PREG_SET_ORDER);

        $workers = collect($matches)->reject(fn (array $match): bool => $match[1] === 'master');
        $running = (int) $workers->sum(fn (array $match): int => (int) $match[2]);

        if ($running === 0) {
            return null;
        }

        $average = (int) round($workers->sum(fn (array $match): int => $match[2] * $match[3]) / $running);
        $php = $server->tuning['php'] ?? null;
        $budget = $php['memory_budget_mb'] ?? null;
        $perSite = $php['secondary_pool']['max_children'] ?? null;
        $sites = $server->sites()->count();

        return [
            'running' => $running,
            'average_mb' => $average,
            'largest_mb' => (int) $workers->max(fn (array $match): int => (int) $match[4]),
            'swage_assumes_mb' => $php['process_size_mb'] ?? ServerTuner::PHP_PROCESS_SIZE_MB,
            'php_memory_budget_mb' => $budget,
            'workers_that_fit_budget' => $budget && $average > 0 ? intdiv($budget, $average) : null,
            'site_pools' => $sites,
            'max_children_per_site_pool' => $perSite,
            'every_site_pool_full_mb' => $perSite ? $sites * $perSite * $average : null,
        ];
    }
}
