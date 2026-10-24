@extends('layout')
@section('title', 'ลงทะเบียนสำเร็จ')
@section('steps', 'done')
@section('content')
    <h1>ลงทะเบียนสำเร็จ</h1>
    <div class="alert alert-info" role="status">
        <strong>บันทึกข้อมูลในหน้านี้ไว้</strong> หน้านี้แสดงได้ครั้งเดียว หากรีเฟรชหรือปิดหน้าจะไม่สามารถกลับมาดูได้
        (กุญแจสาธารณะดูได้ตลอดที่ <a href="{{ route('well-known.keys') }}">{{ route('well-known.keys') }}</a>)
    </div>

    <h2>บัญชีที่ลงทะเบียน</h2>
    <p class="muted">ใช้ account id เพื่อจับคู่กับ <code>data.account.id</code> ใน webhook</p>
    <p class="muted" id="one-account-rule">ผู้ใช้ K BIZ นี้ผูกกับบัญชีนี้แล้วและใช้ลงทะเบียนบัญชีอื่นไม่ได้ หากต้องการเพิ่มบัญชี กรุณาสร้างผู้ใช้ K BIZ ใหม่
        แล้วลงทะเบียนด้วยรหัสลงทะเบียนใหม่</p>
    <table>
        <thead><tr><th scope="col">เลขบัญชี</th><th scope="col">account id</th></tr></thead>
        <tbody>
        @foreach ($results as $result)
            <tr>
                <td><code>{{ $result->maskedNumber ?? '—' }}</code></td>
                <td>
                    <code class="break">{{ $result->accountId }}</code>
                    @if ($result->handover)
                        <p class="hint">รับช่วงบัญชีนี้ต่อจากผู้ใช้ K BIZ เดิม: ใช้ account id เดิม และลำดับ <code>data.sequence</code> นับต่อจากเดิม
                            (รายการแรกที่ส่งถึงคุณคือลำดับถัดจากรายการสุดท้ายที่ส่งให้ผู้ใช้เดิม)
                            แต่เริ่มส่งเฉพาะรายการใหม่เหมือนบัญชีที่ลงทะเบียนครั้งแรก และใช้ webhook endpoint ใหม่ตาม Webhook URL ด้านล่าง
                            (รายการเก่าที่ยังค้างส่งยังคงอยู่กับ Webhook URL ของผู้ใช้เดิม และผู้ดูแลเป็นผู้ตัดสินว่าจะจัดการรายการเหล่านั้นอย่างไร)</p>
                        @if ($result->handoverGap !== null)
                            <div class="alert alert-warning" role="alert">
                                <strong>มีช่วงที่ระบบอาจไม่ได้ส่งรายการให้:</strong>
                                รายการระหว่าง {{ $result->handoverGap->from->format('Y-m-d H:i:s') }} ถึง {{ $result->handoverGap->to->format('Y-m-d H:i:s') }} (เวลาประเทศไทย)
                                อาจไม่ได้ส่งเป็น webhook เพราะมีการเปลี่ยนผู้ใช้ KBiz กรุณาตรวจสอบช่วงนี้กับ statement ธนาคารเอง
                                @if ($result->handoverGap->deliveredCount === 0)
                                    ยังไม่มีรายการในช่วงนี้ที่ส่งสำเร็จ
                                @elseif ($result->handoverGap->deliveredCount !== null)
                                    ในช่วงนี้ส่งสำเร็จแล้ว {{ $result->handoverGap->deliveredCount }} รายการ — กรุณาอย่าบันทึกรายการเหล่านั้นซ้ำ
                                @endif
                                @if ($result->handoverGap->pendingCount > 0)
                                    ยังค้างส่งหรือส่งไม่สำเร็จอีก {{ $result->handoverGap->pendingCount }} รายการ — รายการเหล่านี้อาจไม่ถึงระบบของคุณ กรุณาติดต่อผู้ดูแล
                                @endif
                            </div>
                        @endif
                    @elseif ($result->reattached)
                        <p class="hint">เชื่อมต่อบัญชีเดิมอีกครั้งหลังเซสชัน K BIZ หมดอายุ: ใช้ account id เดิม ลำดับ <code>sequence</code> นับต่อจากเดิม
                            และระบบจะส่งรายการที่เกิดขึ้นระหว่างที่ขาดการเชื่อมต่อ
                            @if ($result->catchUpDays !== null)
                                (ย้อนหลังไม่เกิน {{ $result->catchUpDays }} วัน)
                            @endif
                            ไปที่ Webhook URL ด้านล่าง</p>
                    @endif
                    @if ($result->missed !== null)
                        <div class="alert alert-warning" role="alert">
                            <strong>มีช่วงที่ระบบส่งรายการให้ไม่ได้:</strong>
                            รายการตั้งแต่ {{ $result->missed->from->format('Y-m-d H:i') }} ถึงสิ้นวันที่ {{ $result->missed->lastMissedDay->format('Y-m-d') }} (เวลาประเทศไทย)
                            เก่ากว่าระยะดึงย้อนหลัง {{ $result->catchUpDays }} วัน จึงจะไม่ถูกส่งผ่าน webhook กรุณาตรวจสอบรายการช่วงนี้ใน K BIZ โดยตรง
                        </div>
                    @endif
                    @if ($result->missedUnknown)
                        <div class="alert alert-warning" role="alert">
                            <strong>ยังบอกไม่ได้ว่ามีช่วงที่ระบบส่งรายการให้ไม่ได้หรือไม่:</strong>
                            ระบบอ่านระยะดึงย้อนหลังที่ใช้อยู่ไม่ได้ในขณะนี้ จึงยังไม่ทราบว่ารายการที่เกิดขึ้นระหว่างที่ขาดการเชื่อมต่อ
                            @if ($result->disconnectedSince !== null)
                                (ตั้งแต่ {{ $result->disconnectedSince->format('Y-m-d H:i') }} เวลาประเทศไทย)
                            @endif
                            จะถูกส่งผ่าน webhook ครบหรือไม่ กรุณาตรวจสอบรายการช่วงนี้ใน K BIZ โดยตรง และแจ้งผู้ดูแลระบบ
                        </div>
                    @endif
                </td>
            </tr>
        @endforeach
        </tbody>
    </table>

    <h2>Webhook URL</h2>
    <p><code class="break">{{ $webhookUrl }}</code></p>
    <p class="muted">สำหรับบัญชีที่ลงทะเบียนครั้งแรก ระบบจะส่งเฉพาะรายการที่เกิดขึ้นหลังจากนี้ (รายการที่เกิดก่อนการลงทะเบียนจะไม่ถูกส่ง)
        ทุกคำขอเป็น HTTP POST พร้อม header <code>webhook-id</code>, <code>webhook-timestamp</code>, <code>webhook-signature</code>
        ตอบกลับด้วยสถานะ 2xx เมื่อรับสำเร็จ</p>
    <ul class="muted">
        <li>ระบบส่งแบบ at-least-once: รายการเดียวกันอาจถูกส่งซ้ำ ให้ตัดรายการซ้ำด้วย <code>webhook-id</code></li>
        <li>บันทึกยอดเงินแบบ idempotent ด้วยคู่ <code>data.account.id</code> + <code>data.transaction.ref</code> เพื่อไม่ให้บันทึกซ้ำ</li>
        <li>ลำดับรับประกันเฉพาะภายในบัญชีเดียวกัน (<code>data.sequence</code> เรียงต่อเนื่องไม่ขาดในแต่ละบัญชี) ไม่รับประกันลำดับข้ามบัญชี</li>
    </ul>

    <h2>กุญแจสาธารณะสำหรับตรวจลายเซ็น (Ed25519)</h2>
    <table>
        <thead><tr><th scope="col">kid</th><th scope="col">public key (base64)</th></tr></thead>
        <tbody>
        @foreach ($signingKeys as $key)
            <tr><td><code>{{ $key->kid }}</code></td><td><code class="break">{{ $key->base64() }}</code></td></tr>
        @endforeach
        </tbody>
    </table>
    <p class="muted">ช่วงเปลี่ยนกุญแจ webhook จะมีหลายลายเซ็นคั่นด้วยช่องว่าง ให้ถือว่าถูกต้องหากลายเซ็นใดลายเซ็นหนึ่งตรวจผ่าน</p>

    <h2>ตัวอย่างการตรวจลายเซ็น</h2>
    <p class="muted">ข้อความที่ลงลายเซ็น: <code>{webhook-id}.{webhook-timestamp}.{raw body}</code> ต้องใช้ body ดิบตามที่ได้รับ ห้าม parse แล้ว encode ใหม่</p>
    <h3>Node.js</h3>
    <pre><code>{{ $nodeSnippet }}</code></pre>
    <h3>PHP (ext-sodium)</h3>
    <pre><code>{{ $phpSnippet }}</code></pre>

    <a class="button" href="{{ route('registration.code') }}" aria-describedby="one-account-rule">ลงทะเบียนบัญชีอื่น (ใช้ผู้ใช้ K BIZ ใหม่)</a>
@endsection
