<?php

namespace Swage\AiReview;

use App\Models\Server;
use Illuminate\Database\Eloquent\Collection;
use Swage\AiReview\Models\IgnoredFinding;
use Swage\AiReview\Models\Review;
use Swage\AiReview\Models\ReviewState;

/**
 * The findings of each server's latest review that nobody has ignored, while the server is still reviewed. Servers are
 * read together, in the same few queries however many there are.
 */
class NeedsAttention
{
    /**
     * @param  Collection<int, Server>  $servers
     * @return array<int, array{count: int, severity: Severity}> By server id. Servers with nothing to look at are left out.
     */
    public function for(Collection $servers): array
    {
        $reviewed = ReviewState::query()->whereIn('server_id', $servers->modelKeys())->where('enabled', true)->pluck('server_id')->all();

        if ($reviewed === []) {
            return [];
        }

        $ignored = IgnoredFinding::query()->whereIn('server_id', $reviewed)->get(['server_id', 'key'])->groupBy('server_id');
        $items = [];

        Review::query()
            ->whereIn('id', Review::query()->selectRaw('max(id)')->whereIn('server_id', $reviewed)->groupBy('server_id'))
            ->get(['id', 'server_id', 'findings'])
            ->each(function (Review $review) use ($ignored, &$items): void {
                $keys = $ignored->get($review->server_id)?->pluck('key')->all() ?? [];

                foreach ($review->sortedFindings() as $finding) {
                    if (in_array($finding['key'], $keys, true)) {
                        continue;
                    }

                    $items[$review->server_id] ??= ['count' => 0, 'severity' => $finding['severity']];
                    $items[$review->server_id]['count']++;

                    if ($finding['severity']->rank() > $items[$review->server_id]['severity']->rank()) {
                        $items[$review->server_id]['severity'] = $finding['severity'];
                    }
                }
            });

        return $items;
    }
}
