<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

final class WafInspectorTest extends TestCase
{
    public function testCorpusIsWellFormed(): void
    {
        $rules = \SiteGuard\Core\Waf\Rules::all();
        $this->assertTrue(count($rules) > 0, 'corpus is not empty');
        $seen = [];
        foreach ($rules as $rule) {
            foreach (['rule', 'group', 'severity', 'pattern'] as $key) {
                $this->assertTrue(is_string($rule[$key]) || is_int($rule[$key]), 'rule field present: ' . $key);
            }
            $seen[$rule['rule']] = ($seen[$rule['rule']] ?? 0) + 1;
            $this->assertTrue($rule['severity'] >= 1 && $rule['severity'] <= 5, 'severity in 1..5');
        }
        foreach ($seen as $id => $count) {
            $this->assertSame(1, $count, 'rule id unique: ' . $id);
        }
        // every declared group is represented
        $groups = [];
        foreach ($rules as $rule) {
            $groups[$rule['group']] = true;
        }
        foreach (['sqli', 'xss', 'rce-lfi', 'wp-abuse', 'scanner'] as $group) {
            $this->assertTrue(isset($groups[$group]), 'group present: ' . $group);
        }
    }

    public function testSqliTargetsHitAndBenignPasses(): void
    {
        $this->assertGroupHit('sqli', ['path' => '/products', 'query' => ['id' => "1 UNION SELECT user_pass FROM wp_users--"]]);
        $this->assertGroupHit('sqli', ['path' => '/products', 'query' => ['id' => "1' or '1'='1"]]);
        $this->assertGroupHit('sqli', ['path' => '/search', 'query' => ['s' => "sleep(5)"]]);
        $this->assertGroupHit('sqli', ['path' => '/products', 'query' => ['cat' => '2 and information_schema.tables']]);

        foreach ([
            'select your plan',
            'class of 99',
            'union station',
            'reunion select committee notes',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign must not hit sqli: ' . $benign);
        }
    }

    public function testXssTargetsHitAndBenignPasses(): void
    {
        $this->assertGroupHit('xss', ['query' => ['s' => '<script>alert(1)</script>']]);
        $this->assertGroupHit('xss', ['body' => ['comment' => '<img src=x onerror=alert(1)>']]);
        $this->assertGroupHit('xss', ['query' => ['url' => 'javascript:void(0)']]);
        $this->assertGroupHit('xss', ['body' => ['name' => 'onfocus=alert(document.cookie)']]);

        foreach ([
            'lorem ipsum dolor',
            'a modest javascript handbook review',
            'on the origin of species chapter 3',
            'script club minutes',
        ] as $benign) {
            $this->assertSame([], $this->scan(['query' => ['s' => $benign]]), 'benign must not hit xss: ' . $benign);
        }
    }

    public function testRceTargetsHitAndBenignPasses(): void
    {
        $this->assertGroupHit('rce-lfi', ['path' => '/download', 'query' => ['file' => '../../../../etc/passwd']]);
        $this->assertGroupHit('rce-lfi', ['path' => '/download', 'query' => ['file' => '..%2f..%2fetc%2fshadow']]);
        $this->assertGroupHit('rce-lfi', ['path' => '/download', 'query' => ['file' => 'php://filter/convert.base64-encode/resource=index.php']]);
        $this->assertGroupHit('rce-lfi', ['body' => ['cmd' => 'system($_GET[0])']]);

        foreach ([
            '/downloads/file-2.3.tar.gz',
            'system requirements and setup',
            'my notes on the bash shell',
            'a review of the base64 decoding utility',
        ] as $benign) {
            $this->assertSame([], $this->scan(['path' => $benign, 'query' => ['q' => $benign]]), 'benign must not hit rce: ' . $benign);
        }
    }

    public function testWpAbuseTargetsHitAndBenignPasses(): void
    {
        $this->assertGroupHit('wp-abuse', ['path' => '/wp-json/wp/v2/users']);
        $this->assertGroupHit('wp-abuse', ['path' => '/xmlrpc.php']);
        $this->assertGroupHit('wp-abuse', ['path' => '/wp-config.php.bak']);
        $this->assertGroupHit('wp-abuse', ['path' => '/.env']);
        $this->assertGroupHit('wp-abuse', ['path' => '/wp-content/debug.log']);
        $this->assertGroupHit('wp-abuse', ['path' => '/wp-content/uploads/2026/shell.php']);

        foreach ([
            '/2026/11/hello-world/',
            '/wp-json/wp/v2/posts',
            '/wp-content/uploads/2026/photo.jpg',
            '/xmlrpc-alternatives-article/',
        ] as $benign) {
            $this->assertSame([], $this->scan(['path' => $benign]), 'benign must not hit wp-abuse: ' . $benign);
        }
    }

    public function testScannerToolFingerprintsHit(): void
    {
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'sqlmap/1.8']]);
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'Nikto/2.5.0']]);
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'gobuster/3.6']]);
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'wpscan v3.8']]);
    }

    public function testScannerUaAloneIsNotAProbe(): void
    {
        // design law: a scanner UA alone is never scored as an attack — the hit
        // exists but hasProbeHit() stays false, so Gate cannot act on it alone
        foreach (['sqlmap/1.8', 'Nikto/2.5.0', 'Mozilla/5.0 (X11; Linux x86_64)'] as $ua) {
            $hits = $this->scan(['path' => '/products/widget', 'query' => ['s' => 'blue'], 'headers' => ['user-agent' => $ua]]);
            if (stripos($ua, 'sqlmap') !== false || stripos($ua, 'nikto') !== false) {
                $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hits) === false, 'scanner UA alone is not a probe: ' . $ua);
            } else {
                $this->assertSame([], $hits);
            }
        }
        // a scanner UA paired with a real probe payload IS a probe
        $hits = $this->scan(['path' => '/products', 'query' => ['id' => "1 or 1=1"], 'headers' => ['user-agent' => 'sqlmap/1.8']]);
        $this->assertTrue(count($hits) >= 2, 'probe payload + tool UA yields probe and scanner hits');
        $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hits));
    }

    public function testOrdinaryTrafficIsClean(): void
    {
        $benignRequests = [
            ['path' => '/', 'query' => [], 'body' => [], 'headers' => ['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0']],
            ['path' => '/', 'query' => ['s' => 'union station parking'], 'headers' => ['user-agent' => 'Mozilla/5.0 Android 14']],
            ['path' => '/shop/checkout', 'body' => ['name' => 'Taylor Grey', 'address_1' => 'Class of 99 Avenue', 'city' => 'Springfield', 'plan' => 'select your plan: annual'], 'headers' => ['user-agent' => 'Mozilla/5.0 iPhone']],
            ['path' => '/2026/lorem-ipsum-post/', 'query' => [], 'headers' => ['user-agent' => 'Mozilla/5.0 (Linux) Firefox/127.0']],
            ['path' => '/wp-json/wp/v2/posts', 'query' => ['per_page' => 10], 'headers' => ['user-agent' => 'Mozilla/5.0']],
            ['path' => '/wp-admin/admin-ajax.php', 'body' => ['action' => 'siteguard_collect', 'payload' => '{"type":"pageview","path":"/"}'], 'headers' => ['user-agent' => 'Mozilla/5.0']],
            ['path' => '/search', 'query' => ['s' => 'oranges and lemons 3 = 3 fruits']],
            ['path' => '/about', 'query' => ['who' => 'select your team members page']],
        ];
        foreach ($benignRequests as $i => $request) {
            $hits = $this->scan($request);
            $this->assertSame([], $hits, 'benign request must produce zero hits (case ' . $i . ')');
        }
    }

    public function testEvidenceIsShortAndLocatedNotRaw(): void
    {
        $longPayload = 'xss-probe <script>alert(1)</script> ' . str_repeat('A', 500);
        $hits = $this->scan(['query' => ['s' => $longPayload]]);
        $this->assertTrue(count($hits) > 0, 'probe payload produces hits');
        foreach ($hits as $hit) {
            $this->assertTrue(str_starts_with((string) $hit['evidence'], 'query:s «'), 'evidence names its location');
            $this->assertTrue(strlen((string) $hit['evidence']) < 180, 'evidence stays short');
            $this->assertFalse(str_contains((string) $hit['evidence'], str_repeat('A', 200)), 'raw long payload never stored');
        }
    }

    public function testBodyStringAndNestedShapesAreScanned(): void
    {
        // string bodies (raw) and array bodies (form fields) both reach the inspector
        $this->assertGroupHit('sqli', ['body' => "id=1 union select password from users--"]);
        $this->assertGroupHit('sqli', ['body' => ['field' => '1 union select password']]);
        // numeric-looking values are still scanned
        $this->assertGroupHit('wp-abuse', ['query' => ['author' => '?author=1']]);
    }

    public function testEncodedPayloadsAreDecodedBeforeMatching(): void
    {
        // double-encoded traversal: %252e decodes to %2e, then to '.'
        $this->assertGroupHit('rce-lfi', ['path' => '/download', 'query' => ['file' => '%252e%252e%252f%252e%252e%252fetc%252fpasswd']]);
        // single-encoded script tag
        $this->assertGroupHit('xss', ['query' => ['s' => '%3Cscript%3Ealert(1)%3C/script%3E']]);

        // percent text that decodes to nothing dangerous stays clean
        foreach ([
            'a 100% total discount plan',
            '50%25 off the reunion select committee notes',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign percent text must not hit: ' . $benign);
        }
    }

    public function testDeeplyNestedAndJsonShapesAreScanned(): void
    {
        // three levels of nesting now reach the corpus (one level always did)
        $this->assertGroupHit('sqli', ['body' => ['a' => ['b' => ['c' => '1 union select password from users--']]]]);

        // a JSON object payload is unwrapped and each key scanned as its own field
        $hits = $this->scan(['body' => ['payload' => '{"q":"1 union select password from users--"}']]);
        $sawFlattened = false;
        foreach ($hits as $hit) {
            if (str_starts_with((string) $hit['evidence'], 'body:payload.q «')) {
                $sawFlattened = true;
            }
        }
        $this->assertTrue($sawFlattened, 'JSON payload key is scanned as its own field');

        // benign JSON (the siteguard_collect shape) still stays clean
        $this->assertSame([], $this->scan(['body' => ['action' => 'siteguard_collect', 'payload' => '{"type":"pageview","path":"/"}']]));
    }

    public function testGuideNamedRuleFamiliesHitAndBenignPasses(): void
    {
        // CRS 932: a shell separator anchored to a following command word
        $this->assertRuleHit('rce-command-injection', ['body' => ['comment' => 'run this; cat /etc/passwd']]);
        // CRS 933: a PHP open tag arriving through a request surface
        $this->assertRuleHit('rce-php-injection', ['body' => ['tpl' => '<?php echo $x; ?>']]);
        // CRS 931: a shell-named remote resource pulled into a parameter
        $this->assertRuleHit('rce-rfi-remote-resource', ['query' => ['tpl' => 'https://evil.example/uploads/shell.txt']]);

        // benign: lone separators, ordinary words, and non-shell URLs stay clean
        foreach ([
            'step 1; step 2: cook rice',
            'my blog post about webshell forensics',
            'a review of the base64 decoding utility',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign must not hit the new rules: ' . $benign);
        }
    }

    public function testRuleDepthFamiliesHitAndBenignPasses(): void
    {
        // stacked queries: a second statement smuggled past a closing paren
        $this->assertRuleHit('sqli-stacked-queries', ['query' => ['id' => "1);drop table users"]]);
        // SQL file primitives: load_file() / INTO OUTFILE escalation
        $this->assertRuleHit('sqli-file-ops', ['query' => ['id' => "union select load_file('/etc/passwd')"]]);
        $this->assertRuleHit('sqli-file-ops', ['query' => ['id' => "select * into outfile '/tmp/x'"]]);
        // XSS depth: inline SVG handlers, iframe srcdoc, rendered data URI
        $this->assertRuleHit('xss-svg-injection', ['query' => ['s' => '<svg onload=alert(1)>']]);
        $this->assertRuleHit('xss-svg-injection', ['query' => ['s' => '<svg><animate attributename=href>']]);
        $this->assertRuleHit('xss-iframe-srcdoc', ['query' => ['s' => '<iframe srcdoc="<script>alert(1)</script>">']]);
        $this->assertRuleHit('xss-data-uri-html', ['query' => ['s' => 'data:text/html;base64,PHNjcmlwdD4=']]);
        // /proc/self disclosure and overlong UTF-8 traversal aliases
        $this->assertRuleHit('rce-proc-self', ['query' => ['file' => '/proc/self/environ']]);
        $this->assertRuleHit('rce-overlong-utf8', ['path' => '/download', 'query' => ['file' => '%c0%ae%c0%ae/etc/passwd']]);
        // DB dump / backup pulls
        $this->assertRuleHit('wp-db-dump-probe', ['path' => '/backup.sql']);
        $this->assertRuleHit('wp-db-dump-probe', ['path' => '/db.tar.gz']);

        foreach ([
            'step 1: draft; step 2: review the svg animation article',
            'turning ideas into a finished draft',
            'download the 2.3 tarball from the archives page',
            'an essay about sql and html',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign must not hit depth rules: ' . $benign);
        }
        // archived tarballs that are not db/backup/dump pulls stay clean
        $this->assertSame([], $this->scan(['path' => '/downloads/file-2.3.tar.gz']), 'ordinary archive is clean');
    }

    public function testAutomationFingerprintsAndControlCharsAreEvidenceOnly(): void
    {
        // browser-driver stacks and non-browser clients match scanner rules
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'Mozilla/5.0 HeadlessChrome/126.0.0.0']]);
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'python-requests/2.31.0']]);
        $this->assertGroupHit('scanner', ['headers' => ['user-agent' => 'Go-http-client/2.0']]);

        // design law: those fingerprints alone never satisfy probe thresholds
        foreach (['HeadlessChrome/126.0.0.0', 'python-requests/2.31.0', 'Go-http-client/2.0'] as $ua) {
            $hits = $this->scan(['path' => '/products/widget', 'query' => ['s' => 'blue'], 'headers' => ['user-agent' => $ua]]);
            $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hits) === false, 'automation UA alone is not a probe: ' . $ua);
        }

        // control characters are recorded as count-only anomalies (CR and LF
        // excluded so a multiline textarea stays clean even in evidence)
        $hits = $this->scan(['query' => ['s' => "junk\x00payload"]]);
        $groups = [];
        foreach ($hits as $hit) {
            $groups[$hit['group']] = true;
        }
        $this->assertTrue(isset($groups['anomaly']), 'control chars are anomaly (count-only)');
        $this->assertSame([], $this->scan(['body' => ['comment' => "line one\nline two\r\nline three"]]), 'multiline text stays clean');
    }

    public function testOversizedValueIsAnAnomalyHit(): void
    {
        $hits = $this->scan(['query' => ['junk' => str_repeat('A', 3000)]]);
        $groups = [];
        foreach ($hits as $hit) {
            $groups[$hit['group']] = true;
        }
        $this->assertTrue(isset($groups['anomaly']), 'oversized value is flagged anomaly (count-only group)');
    }

    public function testMalformedPatternNeverBreaksTheCorpus(): void
    {
        // the corpus loader drops a syntactically broken pattern instead of throwing
        $rules = \SiteGuard\Core\Waf\Rules::all();
        foreach ($rules as $rule) {
            $this->assertTrue(@preg_match($rule['pattern'], '') !== false, 'all corpus patterns compile: ' . $rule['rule']);
        }
    }

    public function testVersionCommentAndEncodingAnomaliesHitAndBenignPasses(): void
    {
        // the MySQL version-comment probe: an attack payload anchored on a
        // statement keyword inside /*!N...*/ syntax
        $this->assertRuleHit('sqli-version-comment', ['query' => ['id' => '/*!50000union*/ select password']]);
        // a real backup dump carries no statement keyword and stays clean
        $this->assertSame([], $this->scanQuery('/*!40101 SET NAMES utf8 */'), 'restore-script syntax stays clean');
        // encoding anomalies are count-only: recorded, in the anomaly group
        $this->assertGroupHit('anomaly', ['query' => ['s' => 'a %u002F reference']]);
        $this->assertGroupHit('anomaly', ['query' => ['s' => 'value=%252e%252e trick']]);
        $this->assertGroupHit('anomaly', ['headers' => ['content-type' => 'text/html; charset=ibm037']]);
        $this->assertGroupHit('anomaly', ['query' => ['s' => 'charset=ebcdic payload']]);

        // benign: a plain browser charset header, ordinary percent text, and
        // prose with no encoding layer all stay clean
        $this->assertSame([], $this->scan(['headers' => ['content-type' => 'text/html; charset=utf-8']]), 'plain UTF-8 header is clean');
        foreach ([
            'the reunion notes say 99% is a passing grade',
            'a 50%25 off coupon for the class of 99',
            'my notes on utf-8 encoding and the etymology page',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign must not hit encoding anomalies: ' . $benign);
        }
        // anomalies never satisfy probe thresholds by group
        foreach (['%u002F', '%252e', 'charset=ibm037'] as $only) {
            $hits = $this->scanQuery($only . ' harmless words');
            $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hits) === false, 'encoding anomaly alone is not a probe: ' . $only);
        }
    }

    public function testEntityAndNullByteDecodeLayersReachTheCorpus(): void
    {
        // HTML-entity layers resolve in up to two bounded passes
        $this->assertGroupHit('xss', ['query' => ['s' => '&lt;script&gt;alert(1)&lt;/script&gt;']]);
        $this->assertGroupHit('xss', ['query' => ['s' => '&#x3C;script&#x3E;alert(1)']]);
        $this->assertGroupHit('xss', ['query' => ['s' => '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;']], 'a double-encoded entity still resolves.');
        // null-byte splits rejoin before matching
        $this->assertGroupHit('sqli', ['query' => ['s' => 'UNI%00ON SEL%00ECT']]);
        $this->assertGroupHit('sqli', ['query' => ['s' => "UNI\x00ON SELECT"]]);

        // benign prose that merely mentions the entity or the ampersand
        foreach ([
            'the script &amp; the city review',
            'a guide to html entities and ampersands',
        ] as $benign) {
            $this->assertSame([], $this->scanQuery($benign), 'benign entity prose stays clean: ' . $benign);
        }
    }

    public function testStructuralHeaderAnomaliesAreCountOnly(): void
    {
        // spoofed proxy-routing headers: the NAME itself is the finding
        $hits = $this->scan(['path' => '/shop/checkout', 'headers' => ['x-original-url' => '/wp-admin']]);
        $this->assertTrue(isset($this->groupIndex($hits)['anomaly']), 'routing header is anomaly');
        $this->assertTrue(in_array('anomaly-routing-header', array_column($hits, 'rule'), true), 'routing-header rule fired');
        $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hits) === false, 'a routing header alone is not a probe');

        // request-smuggling pair: both headers together, never one alone
        $pairs = $this->scan(['path' => '/shop/checkout', 'headers' => ['content-length' => '10', 'transfer-encoding' => 'chunked']]);
        $this->assertTrue(in_array('anomaly-smuggling-headers', array_column($pairs, 'rule'), true), 'CL+TE pair is a smuggling anomaly');
        $this->assertSame([], $this->scan(['path' => '/shop/checkout', 'headers' => ['content-length' => '10']]), 'content-length alone is clean');
        $this->assertSame([], $this->scan(['path' => '/shop/checkout', 'headers' => ['transfer-encoding' => 'chunked']]), 'transfer-encoding alone is clean');
    }

    private function groupIndex(array $hits): array
    {
        $groups = [];
        foreach ($hits as $hit) {
            $groups[$hit['group']] = true;
        }
        return $groups;
    }

    private function assertGroupHit(string $group, array $request): void
    {
        $hits = $this->scan($request);
        $groups = [];
        foreach ($hits as $hit) {
            $groups[$hit['group']] = true;
        }
        $this->assertTrue(isset($groups[$group]), 'expected a hit in group ' . $group . ', got: ' . json_encode($groups) . ' for ' . json_encode($request));
    }

    private function assertRuleHit(string $ruleId, array $request): void
    {
        $hits = $this->scan($request);
        $ids = [];
        foreach ($hits as $hit) {
            $ids[$hit['rule']] = true;
        }
        $this->assertTrue(isset($ids[$ruleId]), 'expected a hit from rule ' . $ruleId . ', got: ' . json_encode(array_keys($ids)));
    }

    private function scanQuery(string $value): array
    {
        return $this->scan(['query' => ['s' => $value]]);
    }

    private function scan(array $request): array
    {
        return \SiteGuard\Core\Waf\Inspector::scan($request);
    }
}
