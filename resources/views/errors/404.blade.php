@extends('layout')
@section('title', 'ไม่พบหน้าที่ต้องการ')
@section('content')
    <h1>ไม่พบหน้าที่ต้องการ</h1>
    <p>ลิงก์อาจไม่ถูกต้อง</p>
    <a class="button" href="{{ url('/') }}">กลับไปหน้าแรก</a>
@endsection
