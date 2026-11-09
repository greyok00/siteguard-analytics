<?php
declare(strict_types=1);

namespace SiteGuard\Core\Profile;

/**
 * Pure classification helpers behind the Profiles screen: one request path
 * onto one interest topic, browser capability hints into bands, and a
 * visit-pace label. Everything here runs on data the plugin already collects
 * nowhere else — it reads existing stores, it adds no collection.
 */
final class Segments
{
    /** @var list<string> every interest topic the screen can show */
    public const TOPICS = ['shop', 'article', 'pricing', 'contact', 'docs', 'other'];

    /**
     * Path substrings, first topic with a match wins. Checked in this order
     * so 'pricing' beats 'shop' on a plans page and 'docs' beats 'article'
     * on a documentation post.
     */
    private const TOPIC_RULES = [
        'pricing' => ['pricing', 'price', 'plans', 'quote'],
        'shop' => ['shop', 'store', 'product', 'cart', 'checkout', 'category'],
        'docs' => ['docs', 'documentation', 'kb', 'manual', 'api', 'reference'],
        'article' => ['blog', 'article', 'news', 'post', 'insight', 'essay'],
        'contact' => ['contact', 'about', 'support', 'team'],
    ];

    /** Maps one request path onto one interest topic. */
    public static function topic(string $path): string
    {
        $path = strtolower($path);
        foreach (self::TOPIC_RULES as $topic => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($path, $needle)) {
                    return $topic;
                }
            }
        }
        return 'other';
    }

    /**
     * Rolls path view counts into per-topic totals.
     * @param array<string,int> $views path => views
     * @return array<string,int> topic => views, every topic present
     */
    public static function topicCounts(array $views): array
    {
        $counts = array_fill_keys(self::TOPICS, 0);
        foreach ($views as $path => $hits) {
            $counts[self::topic((string) $path)] += (int) $hits;
        }
        return $counts;
    }

    /**
     * Bands the deviceMemory hint (reported in GB: 0.25, 0.5, 1, 2, 4, 8).
     * @return array<string,int> band => visitor count
     */
    public static function memoryBands(array $profiles): array
    {
        $bands = ['small' => 0, 'mid' => 0, 'large' => 0, 'unknown' => 0];
        foreach ($profiles as $profile) {
            $value = is_array($profile) && isset($profile['mem'])
                ? (string) $profile['mem']
                : '';
            if (!is_numeric($value)) {
                $bands['unknown']++;
                continue;
            }
            $gib = (float) $value;
            $bands[$gib >= 8 ? 'large' : ($gib >= 2 ? 'mid' : 'small')]++;
        }
        return $bands;
    }

    /**
     * Bands the hardwareConcurrency hint. Most phones report 4-8; low is 4
     * or fewer, high is 9 or more.
     * @return array<string,int> band => visitor count
     */
    public static function coresBands(array $profiles): array
    {
        $bands = ['low' => 0, 'mid' => 0, 'high' => 0, 'unknown' => 0];
        foreach ($profiles as $profile) {
            $value = is_array($profile) && isset($profile['cores'])
                ? (string) $profile['cores']
                : '';
            if (!is_numeric($value)) {
                $bands['unknown']++;
                continue;
            }
            $cores = (int) $value;
            $bands[$cores >= 9 ? 'high' : ($cores >= 5 ? 'mid' : 'low')]++;
        }
        return $bands;
    }

    /**
     * One visitor's rhythm: sessions measured against how long the visitor
     * has been seen. A brand-new visitor (first week) is always 'new', so a
     * heavy first browsing week never reads as a 'heavy' regular.
     */
    public static function pace(int $sessions, int $firstSeen, int $now): string
    {
        $week = 7 * 86400;
        if ($sessions <= 0 || $firstSeen <= 0 || $now - $firstSeen < $week) {
            return 'new';
        }
        $perWeek = $sessions / (($now - $firstSeen) / $week);
        return $perWeek < 1 ? 'light' : ($perWeek < 4 ? 'steady' : 'heavy');
    }
}
