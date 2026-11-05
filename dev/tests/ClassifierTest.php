<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Classifier;

/**
 * Tests for the endpoint classifier: path shapes, query hints, and the
 * admin exclusion.
 */
final class ClassifierTest extends TestCase
{
    public function testClassifiesCommonPaths(): void
    {
        $cases = [
            ['/', [], Classifier::HTML],
            ['/about/us/', [], Classifier::HTML],
            ['/blog/post-1/', [], Classifier::HTML],
            ['/wp-login.php', [], Classifier::LOGIN],
            ['/login', [], Classifier::LOGIN],
            ['/account/sign-in/', [], Classifier::LOGIN],
            ['/wp-admin/', [], Classifier::ADMIN],
            ['/wp-admin/admin-post.php', [], Classifier::ADMIN],
            ['/wp-json/wp/v2/posts', [], Classifier::REST],
            ['/feed/', [], Classifier::FEED],
            ['/category/news/feed/', [], Classifier::FEED],
            ['/download/report.pdf', [], Classifier::DOWNLOAD],
            ['/cart/', [], Classifier::CART],
            ['/checkout/', [], Classifier::CHECKOUT],
            ['/order-received/123/', [], Classifier::CHECKOUT],
        ];
        foreach ($cases as [$path, $signals, $expected]) {
            $this->assertSame(
                $expected,
                Classifier::classify(['path' => $path] + $signals),
                'Path ' . $path
            );
        }
    }

    public function testSearchAndQueryDetection(): void
    {
        $this->assertSame(Classifier::SEARCH, Classifier::classify(['path' => '/', 'query' => 's=shoes']));
        $this->assertSame(Classifier::SEARCH, Classifier::classify(['path' => '/search/']));
        $this->assertSame(Classifier::FEED, Classifier::classify(['path' => '/news/', 'query' => 'feed=rss2']));
        $this->assertSame(Classifier::DOWNLOAD, Classifier::classify(['path' => '/shop/', 'query' => 'download_file=7']));
        $this->assertSame(Classifier::API, Classifier::classify(['path' => '/', 'query' => 'wc-ajax=add_to_cart']));
    }

    public function testHintsOverridePath(): void
    {
        $this->assertSame(
            Classifier::REST,
            Classifier::classify(['path' => '/', 'is_rest' => true])
        );
        $this->assertSame(
            Classifier::AJAX,
            Classifier::classify(['path' => '/wp-admin/admin-ajax.php', 'is_ajax' => true])
        );
        $this->assertSame(
            Classifier::UNMANAGED,
            Classifier::classify(['path' => '/wp-cron.php', 'is_cron' => true])
        );
    }

    public function testAdminIsNeverManaged(): void
    {
        $class = Classifier::classify(['path' => '/wp-admin/options-general.php', 'is_admin' => true]);
        $this->assertSame(Classifier::ADMIN, $class);
        $this->assertFalse(
            in_array($class, Classifier::MANAGED, true),
            'wp-admin must not be enforceable.'
        );
    }

    public function testManagedListIsExplicit(): void
    {
        foreach (Classifier::MANAGED as $class) {
            $this->assertFalse(
                in_array($class, [Classifier::ADMIN, Classifier::UNMANAGED], true),
                'A managed class must not include the unenforced classes.'
            );
        }
        $this->assertCount(10, Classifier::MANAGED);
    }
}
