<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProductController;

Route::post('register', "AuthController@register");
Route::post('login', "AuthController@login");

Route::group(['middleware' => ["auth:sanctum"]], function () {
    Route::resources([
        "products" => "ProductController"
    ]);
    Route::post('logout', "AuthController@logout");
});

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
