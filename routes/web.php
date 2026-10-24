<?php

use App\Http\Controllers\RegistrationController;
use App\Http\Controllers\WellKnownKeysController;
use Illuminate\Support\Facades\Route;

Route::controller(RegistrationController::class)->name('registration.')->group(function () {
    Route::get('/', 'showCode')->name('code');
    Route::post('/code', 'submitCode')->middleware('throttle:register-code')->name('code.submit');

    Route::get('/login', 'showLogin')->name('login');
    Route::post('/login', 'submitLogin')->middleware('throttle:bank-login')->block(60, 10)->name('login.submit');

    Route::get('/approve', 'showApproval')->name('approve');
    Route::post('/approve/status', 'approvalStatus')->middleware('throttle:approval-poll')->block(60, 10)->name('approve.status');

    Route::get('/accounts', 'showAccounts')->middleware('throttle:accounts-view')->name('accounts');
    Route::post('/accounts', 'submitAccounts')->middleware('throttle:register-submit')->block(30, 10)->name('accounts.submit');

    Route::post('/restart', 'restart')->name('restart');
});

Route::get('/.well-known/wrapbiz-keys.json', WellKnownKeysController::class)->name('well-known.keys');
