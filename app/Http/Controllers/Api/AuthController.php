<?php

namespace App\Http\Controllers\Api;

use Illuminate\Support\Str;
use App\Http\Controllers\Controller;
use App\Mail\VerificationEmail;
use App\Models\User;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'phone' => 'nullable|string',
            'password' => ['required', 'string', 'min:8', 'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/'],
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $existmail = User::where('email', $request->email)->first();

        if ($existmail) {
            return response()->json(['error' => 'Email already exists'], 422);
        }

        $verificationCode = Str::random(6);

        $user = User::create([
            'first_name' => $request->first_name,
            'last_name' => $request->last_name,
            'email' => $request->email,
            'phone' => $request->phone,
            'password' => Hash::make($request->password),
            'account_balance' => 0,
            'status' => 'actif',
            'role' => 'user',
            'description' => $request->description,
            'verification_code' => $verificationCode,
        ]);

        Mail::to($user->email)->send(new VerificationEmail($user));
        $token = $user->createToken("Resto")->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully. Check your email for verification.',
            'token' => $token
        ], 200);
    }


    public function login(Request $request)
    {
        $login = $request->only('email', 'password');

        $validator = Validator::make($login,[
            'email' =>'required|',
            'password' =>'required|'
        ]);

        if($validator->fails()) {
            return response()->json([
                'error'=>$validator->errors()
            ]);
        }

        if (Auth::attempt($login)) {
            $user = Auth::user();
            $token = $user->createToken("Resto")->plainTextToken;
            return response()->json([
                'success'=>true,
                'token' => $token
            ],200);
        }else {
            return response()->json([
                'error' => 'Unauthorized'
            ],401);
        }
    }


    public function sendResetLinkEmail(Request $request) {
        $request->validate([
            'email'=> 'required|email'
        ]);
        $response = Password::broker()->sendResetLink($request->only('email'));

        if ($response === Password::RESET_LINK_SENT) {
            return response()->json([
                'message'=>'Reset link sent successful'
            ]);
        } else {
            return response()->json([
                'message'=>'Unable to sent reset link'
            ],422);
        }
    }

    public function resetPassword(Request $request) {
        $request->validate([
            'email'=> 'required|email',
            'token'=> 'required|string',
            'password' => ['required', 'string', 'min:8', 'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/'],
        ]);
    
        $credentials = $request->only('email', 'password', 'token');
    
       
        $status = Password::broker()->reset($credentials, function ($user, $password) {
            $user->forceFill([
                'password' => bcrypt($password),
            ])->save();
    
           
            $user->notify(new ResetPasswordNotification($user));
        });
    
        
        if ($status === Password::PASSWORD_RESET) {
            return response()->json([
                'message' => 'Réinitialisation du mot de passe réussie'
            ]);
        } else {
            return response()->json([
                'message' => 'Impossible de réinitialiser le mot de passe'
            ], 422);
        }
    }

    public function logout(Request $request) {

        Auth::logout();

       
        return response()->json([
            "success"=> true,
            "message"=> "Deconnexion réussie",
        ]);

        if (!Auth::logout()) {
            return response()->json([
                "success"=> false,
                "message"=> "Deconnexion non réussie",
            ]);
        }
    }
}
