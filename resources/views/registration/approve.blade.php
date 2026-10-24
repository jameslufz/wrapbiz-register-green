@extends('layout')
@section('title', 'ยืนยันการเข้าสู่ระบบ')
@section('steps', 'approve')
@section('content')
    <h1>สแกน QR เพื่อยืนยันการเข้าสู่ระบบ</h1>
    <ol>
        <li>เปิดแอป K BIZ บนโทรศัพท์</li>
        <li>สแกน QR ด้านล่างและกดอนุมัติการเข้าสู่ระบบ</li>
        <li>รอสักครู่ หน้านี้จะไปยังขั้นตอนถัดไปเอง</li>
    </ol>

    <img class="qr" src="{{ $qrImage }}" alt="QR สำหรับยืนยันการเข้าสู่ระบบ K BIZ">
    <p class="center" id="countdown" aria-live="polite">QR หมดอายุใน <span id="seconds">{{ $secondsLeft }}</span> วินาที</p>
    <p class="center muted" id="status" role="status" aria-live="polite">กำลังรอการอนุมัติ…</p>

    <noscript>
        <div class="alert alert-info">เบราว์เซอร์ปิด JavaScript อยู่ หลังอนุมัติในแอปแล้วกดปุ่มด้านล่าง</div>
        <form method="post" action="{{ route('registration.approve.status') }}">
            @csrf
            <button type="submit">ตรวจสอบสถานะ</button>
        </form>
    </noscript>

    <form method="post" action="{{ route('registration.restart') }}" class="inline-form">
        @csrf
        <button type="submit" class="secondary">ยกเลิกและเริ่มใหม่</button>
    </form>
@endsection
@push('scripts')
    <script nonce="{{ $cspNonce ?? '' }}">
        (function () {
            var statusUrl = @json(route('registration.approve.status'));
            var loginUrl = @json(route('registration.login'));
            var token = document.querySelector('meta[name="csrf-token"]').content;
            var secondsEl = document.getElementById('seconds');
            var statusEl = document.getElementById('status');
            var deadline = Date.now() + Number(secondsEl.textContent) * 1000;
            var pollDelayMs = 2000;
            var done = false;

            var timer = setInterval(function () {
                var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
                secondsEl.textContent = String(left);
                if (left === 0) { clearInterval(timer); }
            }, 1000);

            function finish(url) {
                done = true;
                clearInterval(timer);
                location.assign(url || loginUrl);
            }

            // Self-scheduling so two polls never overlap on the same bank session.
            function poll() {
                if (done) { return; }
                fetch(statusUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'X-CSRF-TOKEN': token, 'Accept': 'application/json' },
                }).then(function (response) {
                    if (response.status === 419) { finish(); return null; }
                    return response.json();
                }).then(function (data) {
                    if (!data) { return; }
                    if (data.state === 'pending' || data.state === 'throttled') {
                        if (data.state === 'throttled') { statusEl.textContent = data.message; }
                        setTimeout(poll, data.state === 'throttled' ? pollDelayMs * 3 : pollDelayMs);
                        return;
                    }
                    if (data.state === 'approved') {
                        statusEl.textContent = 'อนุมัติแล้ว กำลังดึงรายการบัญชี…';
                    } else if (data.message) {
                        statusEl.textContent = data.message;
                    }
                    finish(data.redirect);
                }).catch(function () {
                    statusEl.textContent = 'เชื่อมต่อไม่สำเร็จ กำลังลองใหม่…';
                    setTimeout(poll, pollDelayMs * 2);
                });
            }

            setTimeout(poll, pollDelayMs);
        })();
    </script>
@endpush
