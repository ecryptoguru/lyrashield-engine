<?php
// Synthetic benchmark fixture showing the expected safe pattern.
function loadAccountSafe(string $authenticatedUser, array $account): ?array {
    // CASE:PHP-AUTH-01
    return hash_equals($authenticatedUser, (string) ($account['owner_id'] ?? '')) ? $account : null;
}
