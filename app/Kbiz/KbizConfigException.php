<?php

namespace App\Kbiz;

use RuntimeException;

/**
 * Thrown when a KBIZ_* or WRAPBIZ_* variable is missing or malformed.
 * Messages name the variable, never its value.
 */
final class KbizConfigException extends RuntimeException {}
