<?php
declare(strict_types=1);

/**
 * Minimal collector for a static site.
 *
 * Deploy this on any PHP host and point the beacon at it. It stores
 * pseudonymous pageviews in SQLite by default; swap the PDO DSN for MySQL if
 * the traffic warrants it.
 *
 * This endpoint counts and nothing else. It must be protected by edge rate
 * limits, because a public collector is a free write endpoint.
 */

const TYPES = ['pageview', 'leave'];
const DB_PATH = __DIR__ . '/siteguard-static.sqlite';

header('Content-Type: application/json');
header('Cache-Control: no-store');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo '{"ok":false}';
    return;
}

if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096) {
    http_response_code(413);
    echo '{"ok":false}';
    return;
}

$raw = file_get_contents('php://input', false, null, 0, 4096);
$data = json_decode((string) $raw, true);
if (!is_array($data)) {
    http_response_code(204);
    return;
}

$id = static fn ($v): bool => is_string($v) && preg_match('/^[a-f0-9]{32}$/', $v) === 1;
if (!$id($data['visitor'] ?? null) || !$id($data['session'] ?? null)) {
    http_response_code(204);
    return;
}
$visitor = (string) $data['visitor'];
$session = (string) $data['session'];
$type = (string) ($data['type'] ?? '');
if (!in_array($type, TYPES, true)) {
    http_response_code(204);
    return;
}

$path = (string) ($data['path'] ?? '');
$path = substr(preg_replace('/[\x00-\x1F\x7F]/', '', $path) ?? '', 0, 255);
if ($path === '' || $path[0] !== '/') {
    http_response_code(204);
    return;
}

$referrer = (string) ($data['referrer'] ?? '');
$scheme = strtolower((string) parse_url($referrer, PHP_URL_SCHEME));
$referrer = in_array($scheme, ['http', 'https'], true) ? substr($referrer, 0, 255) : '';

$pdo = new PDO('sqlite:' . DB_PATH);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE IF NOT EXISTS sg_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,
    visitor TEXT NOT NULL,
    session TEXT NOT NULL,
    path TEXT NOT NULL,
    referrer TEXT NOT NULL DEFAULT "",
    ua TEXT NOT NULL DEFAULT "",
    dedupe TEXT NOT NULL UNIQUE
)');

// One row per visitor/session/path/minute. A second page in the same minute
// is a different path and still counts; a replayed beacon is dropped by the
// unique index rather than by a read-then-write race.
$dedupe = hash('sha256', $visitor . '|' . $session . '|' . $type . '|' . $path . '|' . intdiv(time(), 60));

$insert = $pdo->prepare('INSERT OR IGNORE INTO sg_events
    (ts, type, visitor, session, path, referrer, ua, dedupe)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
$insert->execute([
    gmdate('Y-m-d H:i:s'),
    $type,
    $visitor,
    $session,
    $path,
    $referrer,
    substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512),
    $dedupe,
]);

http_response_code(204);
