<?php

/*
 * Router for `php -S`, used by KbizTransportTest to exercise the real curl
 * handler. Each path is one misbehaving-bank scenario; every hit is logged
 * so tests can count requests.
 */

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$log = getenv('TRANSPORT_BANK_LOG');
if (is_string($log) && $log !== '') {
    file_put_contents($log, $path."\n", FILE_APPEND | LOCK_EX);
}

$chunk = str_repeat('A', 64 * 1024);

switch ($path) {
    case '/ok':
        header('Content-Type: application/json');
        echo '{"k_wrap":{"k_state":"WAIT"}}';
        break;

    case '/streamed-oversize':
        header('Content-Type: application/json');
        for ($i = 0; $i < 1024; $i++) {
            echo $chunk;
            flush();
        }
        break;

    case '/declared-oversize':
        header('Content-Type: application/json');
        header('Content-Length: 50000000');
        echo '{}';
        break;

    case '/gzip-bomb':
        header('Content-Type: application/json');
        header('Content-Encoding: gzip');
        echo gzencode(str_repeat('A', 20 * 1024 * 1024), 9);
        break;

    case '/redirect':
        header('Location: /ok', true, 302);
        break;

    default:
        http_response_code(404);
}
