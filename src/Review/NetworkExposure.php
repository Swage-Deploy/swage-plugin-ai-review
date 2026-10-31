<?php

namespace Swage\AiReview\Review;

use Illuminate\Support\Collection;

/**
 * Which services can be reached from other machines, worked out from the listening ports and ufw's rules rather than
 * left to the model, which has reported services listening only on 127.0.0.1 as open to the internet.
 */
class NetworkExposure
{
    /**
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>|null
     */
    public function for(array $snapshot): ?array
    {
        $listening = trim($snapshot['listening'] ?? '');

        if (in_array($listening, ['', 'unavailable'], true)) {
            return null;
        }

        $firewall = $this->firewall(trim($snapshot['firewall'] ?? ''));
        $services = $this->listeners($listening);

        [$public, $local] = $services->partition(fn (array $service): bool => $service['public_addresses'] !== []);

        $public = $public->map(fn (array $service): array => [
            'service' => $service['service'],
            'port' => $service['port'],
            'addresses' => $service['public_addresses'],
            'open_to' => $this->openTo($firewall, $service['protocol'], $service['number']),
        ]);

        [$blocked, $reachable] = $public->partition(fn (array $service): bool => $service['open_to'] === 'nobody');

        return array_filter([
            'firewall' => $firewall['summary'],
            'reachable_from_other_machines' => $reachable->values()->all(),
            'listening_publicly_but_blocked_by_firewall' => $blocked->map(fn (array $service): array => collect($service)->except('open_to')->all())->values()->all(),
            'listening_only_on_this_server' => $local->map(fn (array $service): string => "{$service['service']} on {$service['port']}")->values()->all(),
            'firewall_rules_not_understood' => $firewall['unread'],
        ], fn (mixed $value): bool => $value !== []);
    }

    /**
     * Each service and port, with the addresses other machines could reach it on. IPv4 and IPv6 listeners for the same
     * service and port are one entry.
     *
     * @return Collection<int, array{service: string, protocol: string, number: int, port: string, public_addresses: list<string>}>
     */
    protected function listeners(string $listening): Collection
    {
        return collect(explode("\n", $listening))
            ->map(function (string $line): ?array {
                if (! preg_match('/^(tcp|udp)\s+(\S+):(\d+|\*)(?:\s+(.*))?$/', trim($line), $match) || $match[3] === '*') {
                    return null;
                }

                preg_match_all('/\("([^"]+)"/', $match[4] ?? '', $names);

                return [
                    'service' => implode(', ', array_unique($names[1])) ?: 'unknown',
                    'protocol' => $match[1],
                    'number' => (int) $match[3],
                    'address' => $match[2],
                ];
            })
            ->filter()
            ->groupBy(fn (array $listener): string => "{$listener['service']}|{$listener['protocol']}|{$listener['number']}")
            ->map(fn (Collection $listeners): array => [
                'service' => $listeners[0]['service'],
                'protocol' => $listeners[0]['protocol'],
                'number' => $listeners[0]['number'],
                'port' => "{$listeners[0]['number']}/{$listeners[0]['protocol']}",
                'public_addresses' => $listeners->pluck('address')->reject($this->isLocal(...))->unique()->values()->all(),
            ])
            ->values();
    }

    protected function isLocal(string $address): bool
    {
        $address = trim($address, '[]');

        return str_starts_with($address, '127.') || $address === '::1' || str_ends_with($address, '%lo');
    }

    /**
     * ufw's state, default for incoming connections and incoming rules, from "ufw status verbose".
     *
     * @return array{summary: string, active: ?bool, allows_by_default: bool, rules: list<array{ports: ?list<array{0: int, 1: int}>, protocol: ?string, action: string, from: string}>, unread: list<string>}
     */
    protected function firewall(string $status): array
    {
        $unknown = ['active' => null, 'allows_by_default' => false, 'rules' => [], 'unread' => []];

        if ($status === 'not installed') {
            return ['summary' => 'ufw is not installed', ...$unknown, 'active' => false];
        }

        if (! preg_match('/^Status: (\w+)/m', $status, $state)) {
            return ['summary' => 'ufw could not be read, so what it lets through is unknown', ...$unknown];
        }

        if ($state[1] !== 'active') {
            return ['summary' => 'ufw is inactive, so nothing is blocked', ...$unknown, 'active' => false];
        }

        $allowsByDefault = (bool) preg_match('/^Default: (allow|accept)\b[^,]*\(incoming\)/mi', $status);
        $rules = [];
        $unread = [];

        // The rules follow the "--  ------  ----" line under the To, Action and From headings.
        $lines = explode("\n", $status);
        $header = collect($lines)->search(fn (string $line): bool => (bool) preg_match('/^--[\s-]*$/', trim($line)));

        foreach ($header === false ? [] : array_slice($lines, $header + 1) as $line) {
            if (trim($line) === '') {
                continue;
            }

            $columns = preg_split('/\s{2,}/', trim((string) preg_replace('/\s+#.*$/', '', $line)));

            if (count($columns) < 3 || ! preg_match('/^(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?$/', $columns[1], $action)) {
                $unread[] = trim($line);

                continue;
            }

            if (($action[2] ?? 'IN') !== 'IN') {
                continue;
            }

            $to = trim(str_replace('(v6)', '', $columns[0]));
            $from = str_starts_with($columns[2], 'Anywhere') ? 'anywhere' : trim($columns[2]);

            if (str_starts_with($to, 'Anywhere')) {
                $rules[] = ['ports' => null, 'protocol' => null, 'action' => $action[1], 'from' => $from];
            } elseif (preg_match('/^([\d,:]+)(?:\/(tcp|udp))?$/', $to, $port)) {
                $ranges = array_map(fn (string $part): array => array_map(intval(...), explode(':', $part)) + [1 => (int) $part], explode(',', $port[1]));
                $rules[] = ['ports' => $ranges, 'protocol' => $port[2] ?? null, 'action' => $action[1], 'from' => $from];
            } else {
                $unread[] = trim($line);
            }
        }

        return [
            'summary' => $allowsByDefault ? 'ufw is active and allows incoming connections by default' : 'ufw is active and denies incoming connections by default',
            'active' => true,
            'allows_by_default' => $allowsByDefault,
            'rules' => $rules,
            'unread' => array_values(array_unique($unread)),
        ];
    }

    /**
     * Who ufw lets reach a port: "anywhere", a list of addresses, "nobody", or a note that it can't be told.
     *
     * @param  array<string, mixed>  $firewall
     * @return string|list<string>
     */
    protected function openTo(array $firewall, string $protocol, int $number): string|array
    {
        if ($firewall['active'] === null) {
            return 'unknown: the firewall could not be read';
        }

        if ($firewall['active'] === false) {
            return 'anywhere';
        }

        $from = [];

        foreach ($firewall['rules'] as $rule) {
            $matches = ($rule['protocol'] === null || $rule['protocol'] === $protocol)
                && ($rule['ports'] === null || collect($rule['ports'])->contains(fn (array $range): bool => $number >= $range[0] && $number <= $range[1]));

            if (! $matches) {
                continue;
            }

            // ufw uses the first rule that matches, so a deny for everyone before any allow closes the port.
            if (in_array($rule['action'], ['DENY', 'REJECT'], true)) {
                if ($rule['from'] === 'anywhere' && $from === []) {
                    return 'nobody';
                }

                continue;
            }

            $from[] = $rule['from'];
        }

        return match (true) {
            in_array('anywhere', $from, true), $from === [] && $firewall['allows_by_default'] => 'anywhere',
            $from === [] && $firewall['unread'] !== [] => 'nobody, unless a rule under firewall_rules_not_understood allows it',
            $from === [] => 'nobody',
            default => array_values(array_unique($from)),
        };
    }
}
