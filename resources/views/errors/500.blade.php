@extends('layout')
@section('title', 'ระบบขัดข้อง')
@section('content')
    <h1>ระบบขัดข้อง</h1>
    <p>เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่อีกครั้ง หากยังพบปัญหาโปรดติดต่อผู้ดูแลระบบ</p>
    <a class="button" href="{{ url('/') }}">กลับไปหน้าแรก</a>
@endsection
