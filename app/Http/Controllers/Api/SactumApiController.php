<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\VerifyEmail;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class SactumApiController extends Controller
{

    protected $userId;

    public function checkToken()
    {
        $headers = getallheaders();

        if (isset($headers['Authorization'])) {
            $token11 = explode('|',$headers['Authorization']);
           $hashToken = hash('sha256', $token11[1]);
        //    dd($token11);
            $check = DB::table('personal_access_tokens')->where('token', $hashToken)->select('tokenable_id')->orderBy('id', 'desc')->first();

            if (!isset($check->tokenable_id)) {
                return array("success" => false, "message" => 'token mis matched.', 'data' => '');
            } else {
                $this->userId = $check->tokenable_id;
                return array("success" => true, "message" => 'Token Matched.', 'data' => $this->userId);
            }
        } else {
            return array("success" => false, "message" => 'token blanked.', 'data' => '');
        }
    }

    // Register function
    public function register(Request $request)
    {
        try {

            $request->validate([
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',
                'password_confirm' => 'required|same:password'
            ]);

            $pin = rand(100000, 999999);

            $user = new User();
            $user->name = $request->name;
            $user->email = $request->email;
            $user->password = Hash::make($request->password);
            $user->otp = $pin;
            $user->save();

            Mail::to($request->email)->send(new VerifyEmail($pin));

            $token = $user->createToken('myapptoken')->plainTextToken;

            return new JsonResponse(
                [
                    'success' => true,
                    'message' => 'Successful created user. Please check your email for a 6-digit pin to verify your email.',
                    'token' => $token
                ],
                201
            );
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }



    // verify OTP
    public function verifyOtp(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required',
                'otp' => 'required',
            ]);


            $checkuser = User::where('email', $request->email)->first();
            if ($checkuser != '') {
                if ($checkuser->otp == $request->otp) {
                    $checkuser->otp = null;
                    $checkuser->email_verified_at = now();
                    $checkuser->update();

                    // $select = DB::table('personal_access_tokens')
                    // ->where('email', Auth::user()->email)
                    // ->where('token', $request->token)
                    // ->delete();

                     DB::table('personal_access_tokens')
                    ->where('tokenable_id',$checkuser->id)
                    ->delete();

                    return response()->json([
                        'status' => true,
                        'message' => "Otp Verified Successfully",
                        // 'token' => $checkuser->createToken("API TOKEN")->plainTextToken
                    ], 200);
                } else {
                    return response()->json([
                        'status' => false,
                        'message' => "Wrong OTP",
                        'data' => []
                    ], 404);
                }
            } else {
                return response()->json([
                    'status' => false,
                    'message' => "User Not Found",
                    'data' => []
                ], 404);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }


    // resend OTP

    public function resentOtp(Request $request)
    {
        $checkuser = User::where('email', $request->email)->first();

        if ($checkuser != '') {
            if ($checkuser->email_verified_at != '') {
                return response()->json([
                    'status' => false,
                    'message' => "User Already Verified.",
                    'data' => []
                ], 200);
            }

            $otp = rand(1000, 9999);
            $checkuser->otp = $otp;
            $checkuser->update();

            $data = [
                'otp' => 'Your FirstSales verification code is : ' . $otp,
            ];

            Mail::send('mail.otp', $data, function ($message) use ($checkuser) {
                $message->to($checkuser->email)->subject('Your verification code');
                $message->from(env('MAIL_FROM_ADDRESS'), env('MAIL_FROM_NAME'));
            });

            $userData = [
                'email' => $checkuser->email,
                'otp' => $checkuser->otp,
            ];

            return response()->json([
                'status' => true,
                'message' => "OTP Resend Successfully",
                'data' => $userData,
                'token' => $checkuser->createToken("API TOKEN")->plainTextToken
            ], 200);
        } else {
            return response()->json([
                'status' => false,
                'message' => "User Not Found",
                'data' => []
            ], 404);
        }
    }

    // Login Function 

    public function login(Request $request)
    {

        try {

            $request->validate([
                'email' => 'required',
                'password' => 'required',
            ]);
            
            // $loginUser = User::where('email', $request->email)->first();

            // $token = $loginUser->createToken('myapptoken')->plainTextToken;
            

            if (auth()->attempt(array('email' => $request->email, 'password' => $request->password))) {
                if (auth()->user()->email_verified_at != '') {
                    $user = User::where('email', $request->email)->first();
                    $token = $user->createToken('API TOKEN')->plainTextToken;
                    return response()->json([
                        'status' => true,
                        'message' => "User Login Successfull Done..",
                        'token' =>  $token

                    ], 200);
                }
                else{
                    return response()->json([
                        'status' => false,
                        'message' => "User Not Verified",
                        'data' => []
                    ], 404);
                }

            } else {
                return response()->json([
                    'status' => false,
                    'message' => "Email and Password Wrong",
                    'data' => []
                ], 404);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    // LOGOUT FUNCTION

   public function hello(Request $request)
    {
        $tokenres = $this->checkToken();
        if ($tokenres['success'] == false) {
            return response()->json([
                'status' => false,
                'message' => $tokenres['message'],
                'data' => []
            ]);
        }
       $a = "Neeta Bopche";
       return [
        'message' => 'success',
        'Name' => $a,
    ];
    
    }

    public function profileUpdate(Request $request)
    {
        $tokenres = $this->checkToken();
        if ($tokenres['success'] == false) {
            return response()->json([
                'status' => false,
                'message' => $tokenres['message'],
                'data' => []
            ]);
        }

        $userprofile = User::find($request->id);
        $userprofile->name = $request->name;
        $result = $userprofile->update();

        if ($result) {
            return response()->json([
                'status' => true,
                'message' => "Profile Update Successfully",
            ]);
        } else {
            return response()->json([
                'status' => false,
                'message' => "Failed",
                'data' => []
            ]);
        }
    }
}
