<?php



namespace Zt\Cognito\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Auth\Middleware\Authenticate as Middleware;

use Exception;
use Zt\Cognito\Exceptions\AwsCognitoException;
use Zt\Cognito\Exceptions\NoTokenException;
use Zt\Cognito\Exceptions\InvalidTokenException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class AwsCognitoAuthenticate extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next, $module=null, $right=null)
    {
        try {

            $routeMiddleware = $request->route()->middleware();

            if (empty($routeMiddleware) || (count($routeMiddleware)<1)) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => null], 401);
            } //End if

            $this->authenticate($request);
            return $next($request);
        } catch (Exception $e) {
            if ($e instanceof NoTokenException) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => 'NoTokenException'], 401);
            } //End if

            if ($e instanceof InvalidTokenException) {
                return response()->json(['error' => 'UNAUTHORIZED_REQUEST', 'exception' => 'InvalidTokenException'], 401);
            } //End if

            return response()->json(['error' => $e->getMessage()], 401);
        } //Try-catch ends
    } //Function ends

} //Class ends