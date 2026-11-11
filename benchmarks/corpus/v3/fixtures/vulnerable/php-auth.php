<?php
// Synthetic benchmark fixture. Never deploy this handler.

function loadAccountVulnerable(string $authenticatedUser, array $account): array {
    // CASE:PHP-AUTH-01
    return $account;
}
