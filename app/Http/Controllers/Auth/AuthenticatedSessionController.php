<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Carbon\Carbon;
use App\Mail\SendOtpMail;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;


final class AuthenticatedSessionController extends Controller
{
    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request)
    {
        $request->authenticate();
        $request->session()->regenerate();
        return response()->noContent();
    }
    public function loginOTP(Request $request)
    {
        $validator = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->first();

        // Check if user exists and password is correct
        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Check if the user has verified their email
        if (!$user->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email not verified. Please verify your email.'], 403);
        }

        // Generate and send OTP
        $this->sendOTP($user);

        return response()->json(['message' => 'OTP sent. Please verify the OTP to log in.'], 200);
    }

    public function sendOTP($user)
    {
        $otp = rand(100000, 999999); // Generate a 6-digit OTP
        $user->otp = $otp;
        $user->otp_expires_at = Carbon::now()->addMinutes(5); // OTP expires in 5 minutes
        $user->save();
        
        // Send the OTP via email
        Mail::to($user->email)->send(new SendOtpMail($otp));
        return response()->json([
            'message' => 'OTP sent to your email.',
        ], 200);
    }
      /**
     * Verify the OTP and grant access for user.
     */
    public function verifyOTP(LoginRequest $request)
    {

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['message' => 'No user found with this email.'], 404);
        }

        if ($user->otp !== $request->otp || Carbon::now()->greaterThan($user->otp_expires_at)) {
            throw ValidationException::withMessages([
                'Otp' => ['Invalid or expired OTP.'],
            ]);
        }

        // OTP is valid, clear it
        $user->otp = null;
        $user->otp_expires_at = null;
        $user->save();

        return $this->store($request);
    }
    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): Response
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->noContent();
    }
}
