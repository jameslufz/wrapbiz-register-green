<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\View;
use Symfony\Component\HttpFoundation\Response;

/**
 * Strict CSP (inline script/style only via per-request nonce, images only
 * from self or data: URIs for the QR), no framing, no referrer, no caching
 * of pages that carry registration data.
 */
final class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $nonce = base64_encode(random_bytes(18));
        View::share('cspNonce', $nonce);

        $response = $next($request);

        $headers = $response->headers;
        $headers->set('Content-Security-Policy', implode('; ', [
            "default-src 'none'",
            "script-src 'nonce-{$nonce}'",
            "style-src 'nonce-{$nonce}'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "form-action 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ]));
        $headers->set('X-Frame-Options', 'DENY');
        $headers->set('X-Content-Type-Options', 'nosniff');
        $headers->set('Referrer-Policy', 'no-referrer');
        $headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
        if (! $headers->has('Cache-Control') || ! str_contains((string) $headers->get('Cache-Control'), 'public')) {
            $headers->set('Cache-Control', 'no-store, private');
        }
        if ($request->isSecure()) {
            $headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        return $response;
    }
}
