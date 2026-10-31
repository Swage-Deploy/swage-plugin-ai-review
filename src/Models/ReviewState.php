<?php

namespace Swage\AiReview\Models;

use App\Models\Server;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Whether a server is reviewed, when it last was, and why its last review failed.
 */
#[Table('ai_review_states')]
#[Fillable(['server_id', 'enabled', 'reviewed_at', 'error'])]
class ReviewState extends Model
{
    /**
     * The model's default values for attributes.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'enabled' => false,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'reviewed_at' => 'datetime',
        ];
    }

    public static function for(Server $server): self
    {
        return static::firstOrCreate(['server_id' => $server->id]);
    }

    /**
     * @return BelongsTo<Server, $this>
     */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }
}
