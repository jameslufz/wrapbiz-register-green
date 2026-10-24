@extends('layout')
@section('title', 'เข้าสู่ระบบ K BIZ')
@section('steps', 'login')
@section('content')
    <h1>เข้าสู่ระบบ K BIZ และระบุ Webhook URL</h1>

    <div class="alert alert-info">
        <strong>แนะนำ:</strong> สร้างผู้ใช้ K BIZ แบบ <strong>ดูข้อมูลอย่างเดียว (view-only)</strong> สำหรับการเชื่อมต่อนี้
        ระบบใช้เฉพาะการดูรายการบัญชีและรายการเคลื่อนไหว ไม่มีการทำธุรกรรมใด ๆ
    </div>
    <p class="muted">รหัสผ่านใช้เพียงครั้งเดียวเพื่อเข้าสู่ระบบธนาคาร ระบบไม่บันทึกรหัสผ่านไว้ที่ใด</p>
    <p class="muted">ผู้ใช้ K BIZ หนึ่งคนลงทะเบียนได้หนึ่งบัญชีเท่านั้น หากต้องการรับแจ้งเตือนหลายบัญชี กรุณาใช้ผู้ใช้ K BIZ แยกสำหรับแต่ละบัญชี</p>
    <p class="muted">ลงทะเบียนใหม่เพราะเซสชัน K BIZ หมดอายุ? ให้เข้าสู่ระบบด้วย<strong>ผู้ใช้ K BIZ คนเดิม</strong>ที่ใช้ลงทะเบียนครั้งก่อน แล้วเลือกบัญชีเดิมในขั้นตอนถัดไป
        ระบบจะเชื่อมต่อบัญชีเดิมอีกครั้ง (account id เดิม) หากกรอก Webhook URL ใหม่ ระบบจะเปลี่ยนไปส่งที่ URL ใหม่นี้
        ยกเว้น endpoint เดิมยังมีบัญชีอื่นที่ใช้งานอยู่ ซึ่งจะเปลี่ยน URL ไม่ได้</p>

    @if (session('login_error'))
        <div class="alert alert-error" role="alert">{{ session('login_error') }}</div>
    @endif
    @error('login')
        <div class="alert alert-error" role="alert">{{ $message }}</div>
    @enderror

    <form method="post" action="{{ route('registration.login.submit') }}" id="login-form" novalidate>
        @csrf
        <label for="username">ชื่อผู้ใช้ K BIZ</label>
        <input id="username" name="username" type="text" autocomplete="username" autocapitalize="off" spellcheck="false"
               required maxlength="100" value="{{ old('username') }}" @error('username') aria-invalid="true" aria-describedby="username-error" @enderror>
        @error('username')<p id="username-error" class="field-error" role="alert">{{ $message }}</p>@enderror

        <label for="password">รหัสผ่าน K BIZ</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="200"
               @error('password') aria-invalid="true" aria-describedby="password-error" @enderror>
        @error('password')<p id="password-error" class="field-error" role="alert">{{ $message }}</p>@enderror

        <label for="webhook_url">Webhook URL</label>
        <input id="webhook_url" name="webhook_url" type="url" inputmode="url" autocomplete="url" spellcheck="false" required
               maxlength="2048" placeholder="https://example.com/webhooks/wrapbiz" value="{{ old('webhook_url', $webhookUrl) }}"
               aria-describedby="webhook-hint @error('webhook_url') webhook-error @enderror" @error('webhook_url') aria-invalid="true" @enderror>
        <p id="webhook-hint" class="hint">ต้องเป็น https พอร์ต 443 และเข้าถึงได้จากอินเทอร์เน็ต ระบบจะส่งรายการเงินเข้า-ออกไปที่ URL นี้</p>
        @error('webhook_url')<p id="webhook-error" class="field-error" role="alert">{{ $message }}</p>@enderror

        <button type="submit" id="login-submit">เข้าสู่ระบบและรับ QR</button>
    </form>

    <form method="post" action="{{ route('registration.restart') }}" class="inline-form">
        @csrf
        <button type="submit" class="secondary">ยกเลิกและเริ่มใหม่</button>
    </form>
@endsection
@push('scripts')
    <script nonce="{{ $cspNonce ?? '' }}">
        document.getElementById('login-form').addEventListener('submit', function () {
            var button = document.getElementById('login-submit');
            button.disabled = true;
            button.textContent = 'กำลังเชื่อมต่อธนาคาร…';
        });
    </script>
@endpush
