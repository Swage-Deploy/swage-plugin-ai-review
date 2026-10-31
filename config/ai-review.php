<?php

return [
    // How often, in hours, each server the review is turned on for is reviewed.
    'interval_hours' => (int) env('AI_REVIEW_INTERVAL_HOURS', 6),

    // How long, in seconds, to wait for the API to answer.
    'timeout' => (int) env('AI_REVIEW_TIMEOUT', 120),

    // How many days of reviews are kept.
    'retention_days' => (int) env('AI_REVIEW_RETENTION_DAYS', 30),
];
