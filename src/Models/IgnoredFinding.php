<?php

namespace Swage\AiReview\Models;

use App\Models\Server;
use App\Models\User;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

/**
 * A finding someone has chosen to ignore on a server. Reviews still check for it and still report it, and the panel
 * shows it under Ignored instead of with the findings to act on.
 *
 * Findings are matched by a key the review gives each issue, such as "ssh-password-login", which it is asked to keep
 * the same from one review to the next.
 */
#[Table('ai_review_ignored_findings')]
#[Fillable(['server_id', 'key', 'title', 'ignored_by_id'])]
class IgnoredFinding extends Model
{
    /**
     * The key of a finding: the one the review gave it, or its title when it gave none.
     *
     * @param  array<string, mixed>  $finding
     */
    public static function keyFor(array $finding): string
    {
        $key = Str::slug(mb_substr((string) ($finding['key'] ?? ''), 0, 80));

        if ($key === '') {
            $key = Str::limit(Str::slug((string) ($finding['title'] ?? '')), 80, '');
        }

        return $key !== '' ? $key : 'finding-'.substr(md5((string) ($finding['title'] ?? '')), 0, 12);
    }

    /**
     * @return BelongsTo<Server, $this>
     */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function ignoredBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'ignored_by_id');
    }
}
