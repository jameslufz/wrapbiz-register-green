@extends('layout')
@section('title', 'เซสชันหมดอายุ')
@section('content')
    <h1>เซสชันหมดอายุ</h1>
    <p>เพื่อความปลอดภัย เซสชันจะหมดอายุเมื่อไม่มีการใช้งานสักระยะ กรุณาเริ่มใหม่</p>
    <a class="button" href="{{ url('/') }}">กลับไปหน้าแรก</a>
@endsection
