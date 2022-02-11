<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\User;

class AuthController extends Controller
{
    public function register(Request $Request)
    {
        $fields = $Request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);
        $token = $user->createToken("myToken")->plainTextToken;
        $response = [
            'user' => $user,
            'myToken' => $token
        ];
        return response($response, 201);
    }

    public function login(Request $Request)
    {
        $fields = $Request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);
        $user = User::where('email', $fields['email'])->first();
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                "message" => "Please try to login again"
            ], 401);
        }
        $token = $user->createToken("myToken")->plainTextToken;
        $response = [
            'user' => $user,
            'myToken' => $token
        ];
        return response($response, 201);
    }

    public function logout(Request $Request)
    {

        $user = request()->user();
        $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
        return [
            "message" => "Logged Out"
        ];
    }
}
