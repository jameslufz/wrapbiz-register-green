<?php

namespace App\Kbiz;

use RuntimeException;

/**
 * A response-body sink that refuses to grow past a byte limit while the body
 * is still streaming. Counting happens on the decoded bytes curl writes, so a
 * small compressed response cannot inflate past the limit either.
 *
 * It is a plain stream resource (not a PSR-7 object) because Laravel's fake
 * HTTP layer writes test bodies into the sink with fwrite().
 */
final class BoundedSink
{
    private const string FILTER = 'wrapbiz.bounded-sink';

    private int $bytes = 0;

    private bool $exceeded = false;

    /** @var resource */
    private $stream;

    public function __construct(private readonly int $maxBytes)
    {
        if (! in_array(self::FILTER, stream_get_filters(), true)) {
            stream_filter_register(self::FILTER, BoundedSinkFilter::class);
        }

        $stream = fopen('php://temp', 'w+b');
        if ($stream === false) {
            throw new RuntimeException('Unable to open a temporary response buffer.');
        }
        stream_filter_append($stream, self::FILTER, STREAM_FILTER_WRITE, $this);
        $this->stream = $stream;
    }

    /**
     * @return resource
     */
    public function stream()
    {
        return $this->stream;
    }

    /**
     * Rejects a response up front when it declares a body that is too large.
     */
    public function checkDeclaredLength(string $contentLength): void
    {
        if (ctype_digit($contentLength) && (strlen($contentLength) > 18 || (int) $contentLength > $this->maxBytes)) {
            $this->exceeded = true;

            throw new RuntimeException('Response body exceeds the configured limit.');
        }
    }

    public function exceeded(): bool
    {
        return $this->exceeded;
    }

    /**
     * @internal called by BoundedSinkFilter for every chunk written
     */
    public function accept(int $length): bool
    {
        $this->bytes += $length;
        if ($this->bytes > $this->maxBytes) {
            $this->exceeded = true;
        }

        return ! $this->exceeded;
    }
}
