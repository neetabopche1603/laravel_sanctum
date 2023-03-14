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


    // Register function

    public function register(Request $request)
    {
        try {
            //Validated
            $request->validate([
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',
                'password_confirm' => 'required|same:password'
            ]);

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            if ($user) {
                $verify2 =  DB::table('password_resets')->where([
                    ['email', $request->all()['email']]
                ]);
        
                if ($verify2->exists()) {
                    $verify2->delete();
                }

                else{

                    $pin = rand(100000, 999999);
                    DB::table('password_resets')
                        ->insert(
                            [
                                'email' => $request->all()['email'], 
                                'token' => $pin
                            ]
                        );

                }
               
            }
            
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

            // return response()->json([
            //     'status' => true,
            //     'message' => 'User Created Successfully',
            //     'token' => $user->createToken("API TOKEN")->plainTextToken
            // ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }



    public function verifyEmail(Request $request)
    {
    try{

        $validator = Validator::make($request->all(), [
            'token' => ['required'],
        ]);
    
        if ($validator->fails()) {
            return redirect()->back()->with(['message' => $validator->errors()]);
        }
        $select = DB::table('password_resets')
            ->where('email', Auth::user()->email)
            ->where('token', $request->token);
    
        if ($select->get()->isEmpty()) {
            return new JsonResponse(['success' => false, 'message' => "Invalid PIN"], 400);
        }
    
        $select = DB::table('password_resets')
            ->where('email', Auth::user()->email)
            ->where('token', $request->token)
            ->delete();
    
        $user = User::find(Auth::user()->id);
        $user->email_verified_at = Carbon::now()->getTimestamp();
        $user->save();
    
        return new JsonResponse(['success' => true, 'message' => "Email is verified"], 200);
    }

    catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }    
}
}
