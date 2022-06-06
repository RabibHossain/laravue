<?php

namespace App\Http\Controllers\Api\Auth;

use App\HelperService\Helpers;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use \Illuminate\Http\JsonResponse;

class AuthController extends Controller
{
    private bool $loginAfterSignUp = true;
    private Helpers $helpers;
    private string $created;
    private int $createdCode;
    private string $badRequest;
    private int $badRequestCode;
    private string $unauthorized;
    private int $unauthorizedCode;
    private string $accepted;
    private int $acceptedCode;
    private string $internalError;
    private int $internalErrorCode;

    public function __construct(
        Helpers $helpers
    )
    {
        $this->created = 'Created';
        $this->createdCode = 201;
        $this->badRequest = 'Bad Request';
        $this->badRequestCode = 400;
        $this->unauthorized = 'Unauthorized';
        $this->unauthorizedCode = 401;
        $this->accepted = 'Accept';
        $this->acceptedCode = 200;
        $this->internalError = 'Internal Error';
        $this->internalErrorCode = 500;
        $this->helpers = $helpers;
    }

    protected function createNewToken($token): array
    {
        return [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60
        ];
    }

    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors());
        }

        $user = new User();
        $user->name = $request->get('name');
        $user->email = $request->get('email');
        $plainPassword = $request->get('password');
        $user->password = Hash::make($plainPassword);
        $user->save();

        $response = [
            "user" => $user
        ];
        return $this->helpers->response(true, $this->created, $response, null, $this->createdCode);
    }

    public function login(Request $request): JsonResponse
    {
        $rules = [
            'email.required' => 'Email can not be empty.',
            'password.required' => 'Password can not be empty.'
        ];
        $validator = Validator::make($request->all(), [
            'email' => 'required|string',
            'password' => 'required|string',
        ], $rules);

        if ($validator->fails()) {
            $errors = $validator->errors();
            return $this->helpers->response(false, $this->badRequest, null, $errors, $this->badRequestCode);
        }

        $credentials = $request->only("email", "password");
        $token = null;

        if (!$token = JWTAuth::attempt($credentials)) {
            return $this->helpers->response(false, $this->unauthorized, null, null, $this->unauthorizedCode);
        }


        return $this->helpers->response(true, $this->accepted, $this->createNewToken($token), null, $this->acceptedCode);
    }

    public function logout(Request $request): JsonResponse
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);
            $details = "Logged out";
            return $this->helpers->response(true, $this->accepted, $details, null, $this->acceptedCode);
        } catch (JWTException $exception) {
            $details = "Please try again!";
            return $this->helpers->response(false, $this->internalError, $details, null, $this->internalErrorCode);
        }
    }

    public function getAuthUser(Request $request): JsonResponse
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        $user = JWTAuth::authenticate($request->token);
        $response = [
            "user" => $user
        ];

        return $this->helpers->response(true, $this->accepted, $response, null, $this->acceptedCode);
    }

    public function refresh(): JsonResponse
    {
        $refreshToken = $this->createNewToken(JWTAuth::refresh());
        return $this->helpers->response(true, $this->accepted, $refreshToken, null, $this->acceptedCode);
    }
}
