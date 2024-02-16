<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\RefreshTokenRepository;

class TokenManagementController extends Controller
{
    /**
     * @param $email
     * @param $password
     * @return JsonResponse
     */
    public function tokenAndRefreshToken($email,$password): JsonResponse
    {
        $baseUrl = url('/');
        $response = Http::post("{$baseUrl}/oauth/token", [
            'username' => $email,
            'password' => $password,
            'client_id' => config(('passport.password_grant_client.id')),
            'client_secret' => config(('passport.password_grant_client.secret')),
            'grant_type' => 'password',
        ]);

        $result = json_decode($response->getBody(), true);

        return response()->json($result);
    }


    /**
     * @param $refresh_token
     * @return JsonResponse
     */
    public function refreshToken($refresh_token): JsonResponse
    {

        $baseUrl = url('/');
        $response = Http::post("{$baseUrl}/oauth/token", [
            'refresh_token' => $refresh_token,
            'client_id' => config('passport.password_grant_client.id'),
            'client_secret' => config('passport.password_grant_client.secret'),
            'grant_type' => 'refresh_token',
        ]);

        $result = json_decode($response->getBody(), true);
        if (!$response->ok()) {
            return response()->json(['error' => $result['error_description']], 401);
        }
        return response()->json($result);
    }

    /**
     * @param $token
     * @return JsonResponse
     */
    public function revokeToken($token): JsonResponse
    {
        /* --------------------------- revoke access token -------------------------- */
        $token->revoke();
        $token->delete();

        /* -------------------------- revoke refresh token -------------------------- */
        $refreshTokenRepository = app(RefreshTokenRepository::class);
        $refreshTokenRepository->revokeRefreshTokensByAccessTokenId($token->id);

        return response()->json(['message' => 'Logged out successfully']);

    }


}
