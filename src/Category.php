<?php

namespace Swage\AiReview;

/**
 * What a finding is about.
 */
enum Category: string
{
    case Security = 'security';
    case Performance = 'performance';
    case Reliability = 'reliability';

    public function label(): string
    {
        return match ($this) {
            self::Security => __('Security'),
            self::Performance => __('Performance'),
            self::Reliability => __('Reliability'),
        };
    }

    public function icon(): string
    {
        return match ($this) {
            self::Security => 'shield-check',
            self::Performance => 'bolt',
            self::Reliability => 'heart',
        };
    }
}
