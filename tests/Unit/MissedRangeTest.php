<?php

namespace Tests\Unit;

use App\Registration\MissedRange;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MissedRangeTest extends TestCase
{
    private const string NOW = '2026-10-16T09:00:00+07:00';

    /**
     * @return iterable<string, array{?string, string, ?array{string, string}}>
     */
    public static function watermarks(): iterable
    {
        yield 'never polled' => [null, self::NOW, null];
        yield 'yesterday' => ['2026-10-15T12:00:00+07:00', self::NOW, null];
        yield 'first day still fetched (7 days back)' => ['2026-10-09T00:00:00+07:00', self::NOW, null];
        yield 'the reach day (8 days back) is still fetched' => ['2026-10-08T00:00:00+07:00', self::NOW, null];
        yield 'same instant in UTC is still that Bangkok day' => ['2026-10-07T17:00:00Z', self::NOW, null];
        yield 'one minute before the reach day' => ['2026-10-07T23:59:00+07:00', self::NOW, ['2026-10-07 23:59', '2026-10-07']];
        yield 'long gap' => ['2026-08-01T03:00:00Z', self::NOW, ['2026-08-01 10:00', '2026-10-07']];
        yield 'now just after Bangkok midnight' => ['2026-10-08T12:00:00+07:00', '2026-10-16T17:30:00Z', ['2026-10-08 12:00', '2026-10-08']];
        yield 'clock skew: watermark in the future' => ['2026-10-20T00:00:00+07:00', self::NOW, null];
    }

    /**
     * @param  ?array{string, string}  $expected
     */
    #[DataProvider('watermarks')]
    public function test_missed_range_mirrors_the_worker_catch_up_window(?string $watermark, string $now, ?array $expected): void
    {
        $range = MissedRange::between($watermark === null ? null : new DateTimeImmutable($watermark), new DateTimeImmutable($now), 7);

        if ($expected === null) {
            $this->assertNull($range);

            return;
        }
        $this->assertNotNull($range);
        $this->assertSame($expected, [$range->from->format('Y-m-d H:i'), $range->lastMissedDay->format('Y-m-d')]);
        $this->assertSame(MissedRange::TIMEZONE, $range->from->getTimezone()->getName());
    }

    /**
     * @return iterable<string, array{int, string, ?array{string, string}}>
     */
    public static function catchUpWindows(): iterable
    {
        yield '1 day: yesterday is still fetched' => [1, '2026-10-15T00:00:00+07:00', null];
        yield '1 day: two days back, the reach day, is still fetched' => [1, '2026-10-14T23:00:00+07:00', null];
        yield '1 day: three days back is missed' => [1, '2026-10-13T23:00:00+07:00', ['2026-10-13 23:00', '2026-10-13']];
        yield '31 days: 31 days back is fetched' => [31, '2026-09-15T00:00:00+07:00', null];
        yield '31 days: 32 days back, the reach day, is fetched' => [31, '2026-09-14T08:00:00+07:00', null];
        yield '31 days: 33 days back is missed' => [31, '2026-09-13T08:00:00+07:00', ['2026-09-13 08:00', '2026-09-13']];
        yield '14 days: a 10-day gap is covered' => [14, '2026-10-06T10:00:00+07:00', null];
    }

    /**
     * @param  ?array{string, string}  $expected
     */
    #[DataProvider('catchUpWindows')]
    public function test_the_window_follows_the_configured_catch_up_days(int $days, string $pollingStart, ?array $expected): void
    {
        $range = MissedRange::between(new DateTimeImmutable($pollingStart), new DateTimeImmutable(self::NOW), $days);

        $this->assertSame($expected, $range === null ? null : [$range->from->format('Y-m-d H:i'), $range->lastMissedDay->format('Y-m-d')]);
    }

    public function test_a_non_positive_window_is_a_programming_error(): void
    {
        $this->expectException(InvalidArgumentException::class);

        MissedRange::between(null, new DateTimeImmutable(self::NOW), 0);
    }
}
