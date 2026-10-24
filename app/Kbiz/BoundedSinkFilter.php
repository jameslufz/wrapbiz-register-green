<?php

namespace App\Kbiz;

use php_user_filter;

/**
 * @internal
 */
final class BoundedSinkFilter extends php_user_filter
{
    public function filter($in, $out, &$consumed, bool $closing): int
    {
        $sink = $this->params;
        while ($bucket = stream_bucket_make_writeable($in)) {
            if (! $sink instanceof BoundedSink || ! $sink->accept($bucket->datalen)) {
                return PSFS_ERR_FATAL;
            }
            $consumed += $bucket->datalen;
            stream_bucket_append($out, $bucket);
        }

        return PSFS_PASS_ON;
    }
}
