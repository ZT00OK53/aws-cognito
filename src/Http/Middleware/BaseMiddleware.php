<?php


namespace Zt\Cognito\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Auth\Middleware\Authenticate as Middleware;

use Zt\Cognito\AwsCognito;

use Exception;
use Zt\Cognito\Exceptions\AwsCognitoException;
use Zt\Cognito\Exceptions\NoTokenException;
use Zt\Cognito\Exceptions\InvalidTokenException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

abstract class BaseMiddleware //extends Middleware
{
    
    /**
     * The Cognito Authenticator.
     *
     * @var \Zt\Cognito\AwsCognito
     */
    protected $cognito;


    /**
     * Create a new BaseMiddleware instance.
     *
     * @param  \Zt\Cognito\AwsCognito  $cognito
     *
     * @return void
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }


    /**
     * Check the request for the presence of a token.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     *
     * @return void
     */
    public function checkForToken(Request $request)
    {
        if (! $this->cognito->parser()->setRequest($request)->hasToken()) {
            throw new NoTokenException();
        } //End if
    } //Function ends


    /**
     * Attempt to authenticate a user via the token in the request.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     *
     * @return void
     */
    public function authenticate(Request $request)
    {
        try {
            $this->checkForToken($request);

            if (! $this->cognito->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('aws-cognito', 'User not found');
            } //End if
        } catch (Exception $e) {
            throw $e;
        } //Try-catch ends
    } //Function ends


    /**
     * Set the authentication header.
     *
     * @param  \Illuminate\Http\Response|\Illuminate\Http\JsonResponse  $response
     * @param  string|null  $token
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function setAuthenticationHeader($response, $token = null)
    {
        $token = $token ?: $this->cognito->refresh();
        $response->headers->set('Authorization', 'Bearer '.$token);

        return $response;
    } //Function ends

} //Class ends