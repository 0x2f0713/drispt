<?php

use Illuminate\Http\Request;
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

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
Route::group([
    'prefix' => 'auth',
    'middleware' => 'api'
], function ($router) {
    Route::post('register', 'UserController@register');
    Route::post('login', 'UserController@login');
    Route::group(['middleware' => 'jwt.auth'], function () {
        Route::get('user-info', 'UserController@getUserInfo');
    });
});
Route::group(['prefix' => 'family', 'middleware' => ['jwt.auth']], function () {
    Route::post('create', 'FamilyController@store');
});
