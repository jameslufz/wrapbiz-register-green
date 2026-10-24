@extends('layout')
@section('title', 'รหัสลงทะเบียน')
@section('steps', 'code')
@section('content')
    <h1>ลงทะเบียนรับแจ้งเตือนรายการเงินเข้า-ออก (K BIZ)</h1>
    <p class="muted">กรอกรหัสลงทะเบียนที่ได้รับจากผู้ดูแลระบบ รหัสหนึ่งชุดใช้ได้ครั้งเดียว</p>

    @if ($inProgress)
        <div class="alert alert-info" role="status">
            คุณมีการลงทะเบียนที่ยังทำไม่เสร็จ
            <a href="{{ route($inProgress->route()) }}">ทำต่อจากเดิม</a>
            หรือกรอกรหัสใหม่ด้านล่างเพื่อเริ่มใหม่
        </div>
    @endif

    <form method="post" action="{{ route('registration.code.submit') }}" novalidate>
        @csrf
        <label for="code">รหัสลงทะเบียน</label>
        <input id="code" name="code" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" required
               maxlength="256" @error('code') aria-invalid="true" aria-describedby="code-error" @enderror autofocus>
        @error('code')
            <p id="code-error" class="field-error" role="alert">{{ $message }}</p>
        @enderror
        <button type="submit">ตรวจสอบรหัส</button>
    </form>
@endsection
