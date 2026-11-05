<?php
declare(strict_types=1);

/**
 * Removes PHP comments and docblocks without touching strings or heredocs.
 *
 *     php dev/tools/strip-comments.php file.php [more.php ...]
 *
 * Files are rewritten in place. Newlines inside a removed comment are kept so
 * line numbers in stack traces still point at the same lines. This is a
 * release-packaging step: never run it on the working tree by hand.
 */

$files = array_slice($argv, 1);
if ($files === []) {
    fwrite(STDERR, "usage: strip-comments.php <file> [file ...]\n");
    exit(2);
}

$before = 0;
$after = 0;
foreach ($files as $file) {
    $source = @file_get_contents($file);
    if ($source === false) {
        fwrite(STDERR, "cannot read {$file}\n");
        exit(1);
    }
    $out = '';
    foreach (token_get_all($source) as $token) {
        if (is_array($token)) {
            if ($token[0] === T_DOC_COMMENT && str_contains($token[1], 'Plugin Name:')) {
                // WordPress reads the plugin header from this docblock; a
                // stripped copy is "No valid plugins found".
                $out .= $token[1];
                continue;
            }
            if ($token[0] === T_COMMENT && str_contains($token[1], 'phpcs:')) {
                // Machine-readable annotations: they silence false positives
                // in Plugin Check, so they are code, not prose.
                $out .= $token[1];
                continue;
            }
            if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                $out .= str_repeat("\n", substr_count($token[1], "\n"));
                continue;
            }
            $out .= $token[1];
            continue;
        }
        $out .= $token;
    }
    if (file_put_contents($file, $out) === false) {
        fwrite(STDERR, "cannot write {$file}\n");
        exit(1);
    }
    $before += strlen($source);
    $after += strlen($out);
}

fwrite(STDERR, sprintf(
    "stripped %d PHP files: %d KB -> %d KB (%d%% smaller)\n",
    count($files),
    (int) round($before / 1024),
    (int) round($after / 1024),
    $before > 0 ? (int) round(100 - ($after / $before) * 100) : 0
));
