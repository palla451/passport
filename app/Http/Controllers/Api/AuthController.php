<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use App\Http\Controllers\Api\TokenManagementController;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\RefreshTokenRepository;

class AuthController extends Controller
{

    protected \App\Http\Controllers\Api\TokenManagementController $token;

    public function __construct(TokenManagementController $token)
    {
        $this->token = $token;
    }
    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        //TODO validate

        try {
            User::create([
                'firstname' => $request->firstname,
                'lastname'  => $request->lastname,
                'username'  => $request->username,
                'email'  => $request->email,
                'password'  => bcrypt($request->password),
            ]);
            return response()->json(['message' => "user $request->username created'"]);
        }catch (\Exception $exception){
            return response()->json(['error' => $exception->getMessage()],$exception->getCode());
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function login (Request $request): JsonResponse
    {
        $login = $request->input('email');
        $user = User::where('email', $login)->orWhere('username', $login)->first();

        if (!$user)
            return response()->json(['error' => 'username o email incorrect'],401);

        $request->validate([
            'password' => 'required|min:8',
        ]);

        if (Auth::attempt(['email' => $user->email, 'password' => $request->password]) ||
            Auth::attempt(['username' => $user->username, 'password' => $request->password])) {

        return $this->token->tokenAndRefreshToken($user->email, $request->password);
        } else
            return response()->json(['error' => 'incorrect credentials'],401);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function refresh(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        return $this->token->refreshToken($request->refresh_token);
    }

    /**
     * @return JsonResponse
     */
    public function logout(): JsonResponse
    {
        $token = auth()->user()->token();
        return $this->token->revokeToken($token);
    }

    /**
     * @return JsonResponse
     */
    public function getUser(): JsonResponse
    {
        return response()->json(auth()->user());
    }


    public function getUsers()
    {
        $users = User::all();
        return response()->json($users);
    }


}
