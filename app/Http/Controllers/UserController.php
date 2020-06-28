<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use JWTAuth;
use JWTAuthException;

class UserController extends Controller
{
    private $user;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function guard()
    {
        return Auth::guard();
    }

    public function register(Request $request)
    {
        $user = $this->user->create([
            'name' => $request->get('name'),
            'username' => $request->get('username'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        return response()->json([
            'status' => 200,
            'message' => 'User created successfully',
            'data' => $user,
        ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');
        $token = null;
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_username_or_password'], 422);
            }
        } catch (JWTAuthException $e) {
            return response()->json(['error' => 'failed_to_create_token'], 500);
        }
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ]);
    }

    public function getUserInfo(Request $request)
    {
        $user = JWTAuth::toUser($request->token);
        return response()->json(['result' => $user]);
    }
}
