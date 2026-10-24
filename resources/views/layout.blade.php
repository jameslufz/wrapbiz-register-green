<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="robots" content="noindex, nofollow">
    <title>@yield('title') · ลงทะเบียน wrapbiz (K BIZ)</title>
    <style nonce="{{ $cspNonce ?? '' }}">
        :root { color-scheme: light; --fg:#1b1f24; --muted:#57606a; --line:#d0d7de; --accent:#0a6b3d; --accent-fg:#fff; --err:#b42318; --err-bg:#fef3f2; --info-bg:#eef6f1; }
        * { box-sizing: border-box; }
        body { margin:0; font-family: "Sarabun", "Noto Sans Thai", system-ui, sans-serif; font-size:17px; line-height:1.6; color:var(--fg); background:#f6f8fa; }
        main { max-width: 640px; margin: 0 auto; padding: 24px 16px 48px; }
        .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:24px; }
        h1 { font-size:1.4rem; margin:0 0 4px; }
        h2 { font-size:1.1rem; margin:24px 0 8px; }
        .steps { list-style:none; display:flex; gap:6px; padding:0; margin:0 0 16px; flex-wrap:wrap; font-size:.85rem; color:var(--muted); }
        .steps li { padding:2px 10px; border:1px solid var(--line); border-radius:999px; background:#fff; }
        .steps li[aria-current="step"] { border-color:var(--accent); color:var(--accent); font-weight:600; }
        label { display:block; font-weight:600; margin:16px 0 4px; }
        .hint { color:var(--muted); font-size:.9rem; margin:4px 0 0; }
        input[type=text], input[type=password], input[type=url] { width:100%; padding:10px 12px; font-size:1rem; border:1px solid var(--line); border-radius:8px; }
        input:focus, button:focus, a:focus { outline:3px solid #7cc4a0; outline-offset:2px; }
        button, .button { display:inline-block; margin-top:20px; padding:10px 20px; font-size:1rem; border-radius:8px; border:1px solid var(--accent); background:var(--accent); color:var(--accent-fg); cursor:pointer; text-decoration:none; }
        button.secondary { background:#fff; color:var(--accent); }
        button[disabled] { opacity:.6; cursor:progress; }
        .alert { border-radius:8px; padding:12px 14px; margin:12px 0; }
        .alert-error { background:var(--err-bg); color:var(--err); border:1px solid #fda29b; }
        .alert-info { background:var(--info-bg); border:1px solid #a6d8bd; }
        .alert-warning { background:#fffaeb; color:#7a2e0e; border:1px solid #fec84b; }
        .field-error { color:var(--err); font-size:.9rem; margin:4px 0 0; }
        .qr { display:block; margin:16px auto; width:240px; height:240px; image-rendering:pixelated; border:1px solid var(--line); }
        .center { text-align:center; }
        table { width:100%; border-collapse:collapse; margin-top:8px; }
        th, td { text-align:left; padding:8px; border-bottom:1px solid var(--line); vertical-align:top; }
        code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.85rem; }
        pre { background:#0d1117; color:#e6edf3; padding:12px; border-radius:8px; overflow:auto; max-height:420px; }
        .account { display:flex; gap:10px; align-items:center; padding:10px; border:1px solid var(--line); border-radius:8px; margin-top:8px; }
        .account label { margin:0; font-weight:400; }
        .account .hint { margin:0; }
        .account-unavailable { background:#f6f8fa; border-style:dashed; }
        .account-unavailable .hint { color:#7a2e0e; }
        .inline-form { display:inline; }
        .muted { color:var(--muted); }
        .break { word-break:break-all; }
    </style>
</head>
<body>
<main>
    @hasSection('steps')
        <ol class="steps" aria-label="ขั้นตอนการลงทะเบียน">
            @foreach (['code' => '1. รหัสลงทะเบียน', 'login' => '2. เข้าสู่ระบบ K BIZ', 'approve' => '3. ยืนยันในแอป', 'accounts' => '4. เลือกบัญชี', 'done' => '5. เสร็จสิ้น'] as $key => $label)
                <li @if (trim($__env->yieldContent('steps')) === $key) aria-current="step" @endif>{{ $label }}</li>
            @endforeach
        </ol>
    @endif
    <div class="card">
        @yield('content')
    </div>
</main>
@stack('scripts')
</body>
</html>
