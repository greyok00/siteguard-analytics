<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

/**
 * Dependency-free test case. The host this was built on has PHP 8.4 with
 * pdo_sqlite but no Composer and no PHPUnit, and a test suite that cannot run
 * on the machine it was written on is not a test suite.
 */
abstract class TestCase
{
    public int $assertions = 0;
    /** @var list<string> */
    public array $failures = [];

    public function setUp(): void
    {
    }

    public function tearDown(): void
    {
    }

    public function assertTrue(bool $condition, string $message = ''): void
    {
        $this->assertions++;
        if (!$condition) {
            $this->failures[] = $message !== '' ? $message : 'Expected true.';
        }
    }

    public function assertFalse(bool $condition, string $message = ''): void
    {
        $this->assertTrue(!$condition, $message !== '' ? $message : 'Expected false.');
    }

    public function assertSame(mixed $expected, mixed $actual, string $message = ''): void
    {
        $this->assertions++;
        if ($expected !== $actual) {
            $this->failures[] = sprintf(
                '%s Expected %s, got %s.',
                $message,
                self::dump($expected),
                self::dump($actual)
            );
        }
    }

    public function assertNotSame(mixed $expected, mixed $actual, string $message = ''): void
    {
        $this->assertions++;
        if ($expected === $actual) {
            $this->failures[] = $message !== '' ? $message : 'Values should differ.';
        }
    }

    public function assertNull(mixed $actual, string $message = ''): void
    {
        $this->assertSame(null, $actual, $message);
    }

    public function assertNotNull(mixed $actual, string $message = ''): void
    {
        $this->assertTrue($actual !== null, $message !== '' ? $message : 'Expected a value.');
    }

    public function assertCount(int $expected, array $actual, string $message = ''): void
    {
        $this->assertSame($expected, count($actual), $message);
    }

    public function assertThrows(string $class, callable $fn, string $message = ''): void
    {
        $this->assertions++;
        try {
            $fn();
        } catch (\Throwable $e) {
            if ($e instanceof $class) {
                return;
            }
            $this->failures[] = sprintf('%s Expected %s, got %s.', $message, $class, $e::class);
            return;
        }
        $this->failures[] = sprintf('%s Expected %s, nothing was thrown.', $message, $class);
    }

    private static function dump(mixed $value): string
    {
        if (is_string($value)) {
            return '"' . $value . '"';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_array($value)) {
            return json_encode($value) ?: 'array';
        }
        return (string) $value;
    }
}
