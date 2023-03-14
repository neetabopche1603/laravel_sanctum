<?php

use App\Http\Controllers\Api\SactumApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::controller(SactumApiController::class)->group(function () {
    Route::post('/register', 'register');
    Route::post('/verifyEmail', 'verifyOtp');
    Route::post('/login', 'login');
});

Route::get('hello', [SactumApiController::class, 'hello']);
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/logout',function(){
        auth()->user()->currentAccessToken()->delete();
        return array("success" => false, "message" => 'Logout Success.', 'data' => '');
    });
});
