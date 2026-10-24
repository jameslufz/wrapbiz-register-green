@extends('layout')
@section('title', 'ลองหลายครั้งเกินไป')
@section('content')
    <h1>ลองหลายครั้งเกินไป</h1>
    <p>กรุณารอสักครู่แล้วลองใหม่</p>
    <a class="button" href="{{ url('/') }}">กลับไปหน้าแรก</a>
@endsection
