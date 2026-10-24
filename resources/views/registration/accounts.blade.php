@extends('layout')
@section('title', 'เลือกบัญชี')
@section('steps', 'accounts')
@section('content')
    @php($selectableCount = count(array_filter($states, fn ($state) => $state->selectable())))
    <h1>เลือกบัญชีที่ต้องการรับแจ้งเตือน</h1>
    <p class="muted">เลือกได้ 1 บัญชี ผู้ใช้ K BIZ หนึ่งคนลงทะเบียนได้หนึ่งบัญชีเท่านั้นและเปลี่ยนภายหลังไม่ได้ หากต้องการรับแจ้งเตือนหลายบัญชี
        กรุณาสร้างผู้ใช้ K BIZ แยกสำหรับแต่ละบัญชี บัญชีที่ลงทะเบียนไว้แล้วหรือถูกระงับจะเลือกไม่ได้</p>
    <p class="muted">หากเคยลงทะเบียนบัญชีไว้แล้วแต่เซสชัน K BIZ หมดอายุ (ต้องเข้าสู่ระบบด้วยผู้ใช้ K BIZ คนเดิมกับครั้งก่อน) บัญชีนั้นจะเลือกได้
        ระบบจะเชื่อมต่อบัญชีเดิมอีกครั้งโดยใช้ account id เดิม และส่งรายการที่เกิดขึ้นระหว่างนั้นย้อนหลังได้ตามจำนวนวันที่ระบบกำหนด
        หากมีช่วงที่ส่งย้อนหลังไม่ได้ หน้าถัดไปจะแจ้งช่วงนั้น</p>

    @error('account')
        <div class="alert alert-error" role="alert">{{ $message }}</div>
    @enderror
    @if ($statesUnavailable)
        <div class="alert alert-error" role="alert">
            ระบบตรวจสอบสถานะบัญชีไม่ได้ชั่วคราว จึงยังเลือกบัญชีไม่ได้ กรุณาโหลดหน้านี้ใหม่อีกครั้งในอีกสักครู่
            <a href="{{ route('registration.accounts') }}">โหลดรายการบัญชีใหม่</a>
        </div>
    @elseif ($selectableCount === 0)
        <div class="alert alert-warning" role="status">
            ไม่มีบัญชีในรายการนี้ที่ลงทะเบียนได้ หากต้องการลงทะเบียนบัญชีเหล่านี้ กรุณาติดต่อผู้ดูแล
        </div>
    @endif

    <form method="post" action="{{ route('registration.accounts.submit') }}" id="accounts-form">
        @csrf
        <input type="hidden" name="list" value="{{ $listNonce }}">
        <fieldset>
            <legend>เลือก 1 บัญชีของผู้ใช้ K BIZ นี้</legend>
            @foreach ($accounts as $token => $account)
                @php($state = $states[$token] ?? null)
                @php($selectable = $state !== null && $state->selectable())
                @php($note = $state !== null ? $state->note() : ($statesUnavailable ? null : $notAskedNote))
                <div @class(['account', 'account-unavailable' => ! $selectable])>
                    <input type="radio" name="account" value="{{ $token }}" id="account-{{ $loop->index }}"
                           @if ($note !== null) aria-describedby="account-{{ $loop->index }}-note" @endif
                           @disabled(! $selectable)
                           @checked($selectable && old('account') === $token)>
                    <div>
                        <label for="account-{{ $loop->index }}">
                            <code>{{ $account->number->masked() }}</code>
                            @if ($account->kind !== '')<span class="muted">({{ $account->kind }})</span>@endif
                        </label>
                        @if ($note !== null)
                            <p class="hint" id="account-{{ $loop->index }}-note">{{ $note }}</p>
                        @endif
                    </div>
                </div>
            @endforeach
        </fieldset>
        @if ($selectableCount > 0)
            <button type="submit" id="accounts-submit">ลงทะเบียนบัญชีนี้</button>
        @endif
    </form>

    <form method="post" action="{{ route('registration.restart') }}" class="inline-form">
        @csrf
        <button type="submit" class="secondary">ยกเลิกและเริ่มใหม่</button>
    </form>
@endsection
@push('scripts')
    <script nonce="{{ $cspNonce ?? '' }}">
        document.getElementById('accounts-form').addEventListener('submit', function () {
            var button = document.getElementById('accounts-submit');
            if (button) {
                button.disabled = true;
                button.textContent = 'กำลังลงทะเบียน…';
            }
        });
    </script>
@endpush
