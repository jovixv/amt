<?php

namespace AdminMiddleware\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use GuzzleHttp\Client;

class AdminAuthMiddleware
{
    public function handle(Request $request, Closure $next)
    {

        $requestToken = $request->headers->get('amtToken');

        if ($requestToken === null)
            return response()->json(['message'=>'token for admin-auth not provided, you need check `token` param in your payload.', 'status_code'=>403], 403);

        $tokenFromCache = Cache::get('jovix_amt');

        if ($tokenFromCache !== null && $tokenFromCache === $requestToken)
            return $next($request);

        if ($tokenFromCache === null || $tokenFromCache !== $requestToken){
            try{
                $client = new Client();
                $proxyResponse = $client->request('POST', config('adminMiddleware.host').config('adminMiddleware.endpoint_url'));
                $content = json_decode($proxyResponse->getBody()->getContents());
                $token = $content->token ?? null;

                if ($token === $requestToken){
                    Cache::set('jovix_amt', $token);
                    return $next($request);
                }else{
                    return response()->json(['message'=>'access denied, token mismatch', 'status_code'=>403], 403);
                }

            }catch (\Exception $exception){
                $statusCode = ($exception->getCode() > 0 ) ? $exception->getCode() : 500;
                return response()->json(['message'=>'Can not get token from proxy server: '.$exception->getMessage(), 'status_code'=>$exception->getCode()], $statusCode);
            }

        }
        return response()->json(['message' => 'Can not process request', 'status_code'=>500], 500);
    }
}
