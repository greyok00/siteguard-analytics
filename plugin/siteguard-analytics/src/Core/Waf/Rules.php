<?php
declare(strict_types=1);

namespace SiteGuard\Core\Waf;

/**
 * The immutable rule corpus for request inspection. Rules are grouped, carry a
 * severity from 1 (anomaly) to 5 (unambiguous attack probe), and compile to
 * case-insensitive patterns once. Inspector consumes this list; Gate scores it.
 */
final class Rules
{
    public const GROUP_SQLI = 'sqli';
    public const GROUP_XSS = 'xss';
    public const GROUP_RCE = 'rce-lfi';
    public const GROUP_WP = 'wp-abuse';
    public const GROUP_SCANNER = 'scanner';
    public const GROUP_ANOMALY = 'anomaly';
    /** Stored browser-fingerprint contradictions (Fingerprint::hits), not pattern matches. */
    public const GROUP_PROFILE = 'profile';

    public const SEVERITY_LOW = 1;
    public const SEVERITY_MEDIUM = 3;
    public const SEVERITY_HIGH = 4;
    public const SEVERITY_CRITICAL = 5;

    /**
     * @return list<array{rule: string, group: string, severity: int, pattern: string}>
     */
    public static function all(): array
    {
        $rules = [
            // SQL injection probes. Classic tautologies and time-based payloads
            // dominate real scanner traffic; exotic syntax is left to higher
            // layers to avoid punishing legitimate query strings.
            ['sqli-union-select', self::GROUP_SQLI, self::SEVERITY_HIGH,
                '/\bunion\b[\s+%20\/\*+]+\bselect\b/i'],
            ['sqli-tautology', self::GROUP_SQLI, self::SEVERITY_HIGH,
                "/\b(?:or|and)\b[\s+%20\/\*+]*\d+[\s+%20\/\*+]*=[\s+%20\/\*+]*\d+/i"],
            ['sqli-tautology-quotes', self::GROUP_SQLI, self::SEVERITY_HIGH,
                "/'\s*(?:or|and)\s*'[^']*'\s*=\s*'/i"],
            ['sqli-time-based', self::GROUP_SQLI, self::SEVERITY_CRITICAL,
                '/\b(?:sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(/i'],
            ['sqli-inference', self::GROUP_SQLI, self::SEVERITY_HIGH,
                '/\binformation_schema\b|\bconcat_ws\s*\(|\bextractvalue\s*\(|\bupdatexml\s*\(/i'],
            ['sqli-comment-tamper', self::GROUP_SQLI, self::SEVERITY_MEDIUM,
                '/(?:\-\-|#|%23|%2D%2D)\s*$/i'],

            // Stacked queries (a second statement smuggled past a closing
            // paren) and file primitives (load_file / INTO OUTFILE) are the
            // injection shapes a UNION probe escalates to; both anchors are
            // syntax, so benign prose never carries them.
            ['sqli-stacked-queries', self::GROUP_SQLI, self::SEVERITY_HIGH,
                '/\)\s*;\s*(?:select|insert|update|delete|drop|truncate|create)\b/i'],
            ['sqli-file-ops', self::GROUP_SQLI, self::SEVERITY_HIGH,
                '/\bload_file\s*\(|\binto\s+(?:out|dump)file\b/i'],

            // XSS payloads: script injection, event-handler injection, and the
            // classic URI schemes.
            ['xss-script-tag', self::GROUP_XSS, self::SEVERITY_HIGH,
                '/<\s*script\b/i'],
            ['xss-event-handler', self::GROUP_XSS, self::SEVERITY_MEDIUM,
                '/\bon(?:error|load|click|mouseover|focus|blur|submit|toggle)\s*=/i'],
            ['xss-javascript-scheme', self::GROUP_XSS, self::SEVERITY_MEDIUM,
                '/javascript\s*:/i'],
            ['xss-dom-gadgets', self::GROUP_XSS, self::SEVERITY_MEDIUM,
                '/document\s*\.\s*cookie\s*\.\s*write|eval\s*\(\s*atob|document\s*\.\s*write\s*\(\s*(?:document|window)\s*\./i'],
            ['xss-tag-injection', self::GROUP_XSS, self::SEVERITY_LOW,
                '/<img\b[^>]*\bsrc\b[^>]*=|<iframe\b|<object\b[^>]*\bdata\b/i'],

            // XSS depth: inline SVG handlers, the iframe srcdoc slot (a raw
            // HTML sandbox bypass), and the one data URI a browser renders as
            // markup. Each anchor is markup-shaped, not a bare word, so a
            // blog post ABOUT these features stays clean.
            ['xss-svg-injection', self::GROUP_XSS, self::SEVERITY_HIGH,
                '/<svg\b[^>]*\bon\w+\s*=|<animate\b[^>]*\battributename\s*=/i'],
            ['xss-iframe-srcdoc', self::GROUP_XSS, self::SEVERITY_MEDIUM,
                '/\bsrcdoc\s*=/i'],
            ['xss-data-uri-html', self::GROUP_XSS, self::SEVERITY_MEDIUM,
                '/data\s*:\s*text\/html/i'],

            // Remote execution and file disclosure probes: traversal, wrappers,
            // and the two paths every fuzzer asks for.
            ['rce-traversal', self::GROUP_RCE, self::SEVERITY_HIGH,
                '/(?:\.\.\/|\.\.\\\\|%2e%2e(?:%2f|%5c|\/|\\\\)/i'],
            ['rce-passwd-file', self::GROUP_RCE, self::SEVERITY_CRITICAL,
                '/\/etc\/(?:passwd|shadow|hosts)\b|%2fetc%2f(?:passwd|shadow)/i'],
            ['rce-wrappers', self::GROUP_RCE, self::SEVERITY_CRITICAL,
                '/php:\/\/(?:input|filter|expect)|data\:\/\/text\/plain/i'],
            ['rce-function-passthrough', self::GROUP_RCE, self::SEVERITY_HIGH,
                '/\b(?:system|passthru|shell_exec|proc_open|popen)\s*\(/i'],
            ['rce-base64-decode-uri', self::GROUP_RCE, self::SEVERITY_MEDIUM,
                '/base64_decode\s*\(\s*["\'$_]/i'],

            // /proc/self reads (environ, cmdline, fd) are pure LFI targets,
            // and overlong UTF-8 traversal (%c0%af = "/") defeats naive
            // decode-then-compare filters. Neither literal appears in
            // ordinary traffic, so both stay false-positive-free.
            ['rce-proc-self', self::GROUP_RCE, self::SEVERITY_CRITICAL,
                '/\/proc\/self\/(?:environ|cmdline|status|fd)\b/i'],
            ['rce-overlong-utf8', self::GROUP_RCE, self::SEVERITY_MEDIUM,
                '/%c0%af|%c1%9c|%c0%ae/i'],

            // CRS 932: a shell separator anchored to a following command word,
            // the shape the guide names as the command-injection family. The
            // anchor word is what keeps lone semicolons in benign text clean.
            ['rce-command-injection', self::GROUP_RCE, self::SEVERITY_HIGH,
                '/(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|zsh|perl|python\d?|php|chmod|chown|rm|mv|kill|ping|sleep)\b/i'],

            // CRS 933: PHP open tags arriving through request surfaces.
            ['rce-php-injection', self::GROUP_RCE, self::SEVERITY_HIGH,
                '/<\?(?:php\b|=)/i'],

            // CRS 931: a remote resource named like a shell being pulled into
            // a parameter (remote file inclusion). Narrow shell-flavored
            // naming, because ordinary outbound URLs in parameters are benign.
            ['rce-rfi-remote-resource', self::GROUP_RCE, self::SEVERITY_HIGH,
                '/\b(?:https?|ftps?):\/\/[^\s\'"<>]{0,160}\b(?:shell|c99|r57|b374k|webshell|rce|backdoor)\b/i'],

            // WordPress-specific abuse: misuse of legit endpoints and probes
            // for files that should never exist.
            ['wp-users-enumeration', self::GROUP_WP, self::SEVERITY_MEDIUM,
                '/wp-json\/wp\/v2\/users(?:\/|$)|(?:^|[?&])author=\d+/i'],
            ['wp-config-probe', self::GROUP_WP, self::SEVERITY_CRITICAL,
                '/wp-config\s*\.(?:php)?[\.\-]*(?:bak|orig|save|old|txt|~)/i'],
            ['wp-config-direct', self::GROUP_WP, self::SEVERITY_CRITICAL,
                '/\/wp-config\.(?:php|bak|txt)(?:$|[?\/])/i'],
            ['wp-env-dotfile-probe', self::GROUP_WP, self::SEVERITY_HIGH,
                '/\/\.env(?:$|[?.])|\/\.git\/(?:config|head)(?:$|[?])|\/\.htaccess(?:$|\?)/i'],
            ['wp-xmlrpc-usage', self::GROUP_WP, self::SEVERITY_LOW,
                '/\/xmlrpc\.php(?:$|\?)/i'],
            ['wp-shell-upload-probe', self::GROUP_WP, self::SEVERITY_HIGH,
                '/(?:uploads?|wp-content|wp-includes)\/.+\.php[0-9]?(?:$|\?)|\/.+\.phtml(?:$|\?)/i'],
            ['wp-file-edit-probe', self::GROUP_WP, self::SEVERITY_HIGH,
                '/\/wp-json\/wp\/v2\/(?:plugins|themes|users)\/[^\/]+\/(?:context|file)/i'],
            ['wp-debug-log-probe', self::GROUP_WP, self::SEVERITY_MEDIUM,
                '/\/wp-content\/(?:debug\.log|wp-content-debug\.log)/i'],
            ['wp-install-probe', self::GROUP_WP, self::SEVERITY_HIGH,
                '/\/wp-(?:admin\/setup-config|admin\/install|config\.php\.sample|mail\.log)/i'],
            ['wp-db-dump-probe', self::GROUP_WP, self::SEVERITY_HIGH,
                '/\.sql(?:\.gz)?(?:$|\?)|\/(?:db|backup|dump)\.(?:zip|tar\.gz|tgz)(?:$|\?)/i'],

            // Scanner tool fingerprints. A UA alone is never a block: Gate only
            // acts on scanner rules when the request ALSO matched a probe-path
            // signature, so fingerprinted-but-innocent clients pass.
            ['scan-nikto', self::GROUP_SCANNER, self::SEVERITY_MEDIUM,
                '/\bnikto\b|\bnessus(?:w|s)?\b|\bnuclei\b/i'],
            ['scan-sqli-tools', self::GROUP_SCANNER, self::SEVERITY_HIGH,
                '/\bsqlmap\b|\bhavij\b|\bsqlninja\b/i'],
            ['scan-dirs-tools', self::GROUP_SCANNER, self::SEVERITY_MEDIUM,
                '/\bgobuster\b|\bdirbuster\b|\bdirb\b|\bferoxbuster\b|\bwfuzz\b|\bffuf\b/i'],
            ['scan-general', self::GROUP_SCANNER, self::SEVERITY_LOW,
                '/\bmasscan\b|\bzgrab\b|\bwhatweb\b|\bwpscan\b|\bhydra\b|\bmedusa\b|\bnmap\s+script/i'],

            // Automation fingerprints: browser-driver stacks and the generic
            // non-browser clients mass scanners use. Scanner group, so a hit
            // alone never blocks - it enriches evidence when a real probe
            // also matched, and fingerprinted-but-innocent clients pass.
            ['scan-headless-automation', self::GROUP_SCANNER, self::SEVERITY_MEDIUM,
                '/\bpuppeteer\b|\bplaywright\b|\bselenium\b|\bphantomjs\b|\bheadlesschrome\b|\bchrome-headless\b/i'],
            ['scan-api-clients', self::GROUP_SCANNER, self::SEVERITY_LOW,
                '/\bpython-requests\/|\bgo-http-client\b|\bokhttp\/|\blibwww-perl\b/i'],

            // Count-only anomalies. Never block on their own (Gate adds a score
            // bonus, and the limit for standalone escalation stays off).
            ['anomaly-oversize-param', self::GROUP_ANOMALY, self::SEVERITY_LOW,
                '/.{2048,}/'],

            // Control characters (NULL bytes in particular) that no decoded
            // HTTP surface should carry. Deliberately excludes CR and LF so a
            // multiline textarea body is not even recorded; count-only.
            ['anomaly-control-chars', self::GROUP_ANOMALY, self::SEVERITY_LOW,
                '/[\x00-\x08\x0b\x0c\x0e-\x1f]/i'],

            // MySQL version-comment syntax (a real 50000union payload is
            // anchored on a statement keyword; a backup dump's /*!40101 SET
            // carries no keyword, so restore scripts stay clean). The digits
            // are required (real version comments always carry a number) and
            // no leading \b exists because the keyword abuts those digits.
            // Probing this pattern IS an SQLi attempt, so it lands in sqli.
            ['sqli-version-comment', self::GROUP_SQLI, self::SEVERITY_HIGH,
                '/\*!\d+[\s+]*(?:union|select|insert|update|delete|or|and|concat|sleep|from)\b/i'],

            // Count-only encoding anomalies: IIS-era %uXXXX escapes and a
            // percent sign that is itself encoded ("%25xx"). Ordinary text that
            // merely contains "50%25 off" survives, because 'o' is not a hex
            // digit; only a real second-encoding layer matches. Neither rule
            // ever blocks alone.
            ['anomaly-unicode-escape', self::GROUP_ANOMALY, self::SEVERITY_LOW,
                '/%u[0-9a-f]{4}/i'],
            ['anomaly-double-encoding', self::GROUP_ANOMALY, self::SEVERITY_LOW,
                '/%25[0-9a-f]{2}/i'],

            // Character-set abuse: naming EBCDIC code pages or a wide encoding
            // on a request surface is the canonical WAF-evasion trick (an
            // overlong or shifted byte stream slips past decode-then-compare).
            // A browser's plain "charset=UTF-8" never matches. Count-only.
            ['anomaly-charset-abuse', self::GROUP_ANOMALY, self::SEVERITY_LOW,
                '/charset\s*=\s*"?(?:ibm0?\d{2,4}|cp0?\d{3,4}|ebcdic|utf-16|utf-32)/i'],
        ];

        $out = [];
        foreach ($rules as [$rule, $group, $severity, $pattern]) {
            $compiled = @preg_match($pattern, '');
            if ($compiled === false) {
                continue; // a broken pattern must never take the corpus down
            }
            $out[] = ['rule' => $rule, 'group' => $group, 'severity' => $severity, 'pattern' => $pattern];
        }
        return $out;
    }

    /**
     * The group for one rule id, for incident chips and probes. Fingerprint
     * rules ("fp-*") belong to the profile group without being patterns;
     * rate-limit rows (rate_10s, breadth_600s) and anything unknown answer
     * their plain families rather than a corpus group.
     */
    public static function groupOf(string $rule): string
    {
        if ($rule === '') {
            return '';
        }
        if (str_starts_with($rule, 'fp-')) {
            return self::GROUP_PROFILE;
        }
        foreach (self::all() as $entry) {
            if ($entry['rule'] === $rule) {
                return $entry['group'];
            }
        }
        if (str_starts_with($rule, 'rate_') || str_starts_with($rule, 'breadth_')) {
            return 'rate';
        }
        return '';
    }
}
