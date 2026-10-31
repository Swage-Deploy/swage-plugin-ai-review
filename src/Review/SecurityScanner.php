<?php

namespace Swage\AiReview\Review;

use App\Models\Server;
use App\Servers\ServerIntegrations;

/**
 * The security scanner plugin, when it is installed. Its records of attacks on a server, and what the review needs to
 * know to read them, come from the scanner itself through its ReviewRecords class, so they stay in step with how the
 * scanner works. The review runs without them when the scanner isn't installed, or is too old to offer them.
 */
class SecurityScanner
{
    public const string RECORDS = 'Swage\\SecurityScanner\\ReviewRecords';

    public function installed(): bool
    {
        return array_key_exists('security-scanner', app(ServerIntegrations::class)->all());
    }

    public function offersRecords(): bool
    {
        return $this->installed() && class_exists(self::RECORDS);
    }

    /**
     * What the review is sent about the scanner on the server: its records while it scans the server, otherwise
     * whether it could.
     *
     * @return array<string, mixed>
     */
    public function for(Server $server): array
    {
        if (! $this->installed()) {
            return ['installed' => false];
        }

        if (! $this->offersRecords()) {
            return ['installed' => true, 'shares_records' => false];
        }

        $records = app(self::RECORDS)->for($server);

        return $records === null
            ? ['installed' => true, 'scanning_this_server' => false]
            : ['installed' => true, 'scanning_this_server' => true, ...$records];
    }

    /**
     * What the review is told about reading the scanner's records.
     */
    public function instructions(): ?string
    {
        return $this->offersRecords() ? app(self::RECORDS)->instructions() : null;
    }
}
