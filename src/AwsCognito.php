<?php

namespace Zt\Cognito;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Password;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

use Zt\Cognito\AwsCognitoClaim;
use Zt\Cognito\AwsCognitoManager;
use Zt\Cognito\Http\Parser\Parser;

use Exception;
use Zt\Cognito\Exceptions\AwsCognitoException;
use Zt\Cognito\Exceptions\InvalidTokenException;

class AwsCognito
{
    /**
     * The authentication provider.
     *
     * @var \Zt\Cognito\Contracts\Providers\Auth
     */
    protected $auth;


    /**
     * Aws Cognito Manager
     *
     * @var \Zt\Cognito\AwsCognitoManager
     */
    protected $manager;


    /**
     * The HTTP parser.
     *
     * @var \Zt\Cognito\Http\Parser\Parser
     */
    protected $parser;


    /**
     * The AwsCognito Claim token
     * 
     * @var \Zt\Cognito\AwsCognitoClaim|null
     */
    protected $claim;


    /**
     * The AWS Cognito token.
     *
     * @var \Zt\Cognito\AwsCognitoToken|string|null
     */
    protected $token;


    /**
     * JWT constructor.
     *
     * @param  \Zt\Cognito\Manager  $manager
     * @param  \Zt\Cognito\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(AwsCognitoManager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }


    /**
     * Get the token.
     *
     * @return \Zt\Cognito\AwsCognitoToken|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (AwsCognitoException $e) {
                $this->token = null;
            }
        } //End if

        return $this->token;
    } //Function ends


    /**
     * Parse the token from the request.
     *
     * @throws \Zt\Cognito\Exceptions\AwsCognitoException
     *
     * @return \Zt\Cognito\AwsCognito
     */
    public function parseToken()
    {
        //Parse the token
        $token = $this->parser->parseToken();

        if (empty($token)) {
            throw new AwsCognitoException('The token could not be parsed from the request');
        } //End if

        return $this->setToken($token);
    } //Function ends


    /**
     * Set the token.
     *
     * @param  \string  $token
     *
     * @return \Zt\Cognito\AwsCognito
     */
    public function setToken(string $token)
    {
        $this->token = (new AwsCognitoToken($token));
        if (empty($this->token)) {
            throw new AwsCognitoException('The token could not be validated.');
        } //End if

        return $this;
    } //Function ends


    /**
     * Get the token.
     *
     * @return \Zt\Cognito\AwsCognitoClaim|null
     */
    public function getClaim()
    {
        return (!empty($this->claim))?$this->claim:null;
    } //Function ends


    /**
     * Set the claim.
     *
     * @param  \Zt\Cognito\AwsCognitoClaim  $claim
     *
     * @return \Zt\Cognito\AwsCognito
     */
    public function setClaim(AwsCognitoClaim $claim)
    {
        $this->claim = $claim;
        $this->token = $this->setToken($claim->getToken());

        return $this;
    } //Function ends


    /**
     * Unset the current token.
     *
     * @return \Zt\Cognito\AwsCognito
     */
    public function unsetToken($forceForever = false)
    {
        $tokenKey = $this->token->get();
        $this->manager->release($tokenKey);
        $this->claim = null;
        $this->token = null;

        return $this;
    } //Function ends


    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Zt\Cognito\AwsCognito
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    } //Function ends


    /**
     * Get the Parser instance.
     *
     * @return \Zt\Cognito\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    } //Function ends


    /**
     * Authenticate a user via a token.
     *
     * @return \Zt\Cognito\AwsCognito|false
     */
    public function authenticate()
    {
        $claim = $this->manager->fetch($this->token->get())->decode();
        $this->claim = $claim;

        if (empty($this->claim)) {
            throw new InvalidTokenException();
        } //End if

        return $this; //->user();
    } //Function ends


    /**
     * Alias for authenticate().
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    } //Function ends


    /**
     * Get the authenticated user.
     * 
     * @throws InvalidTokenException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function user()
    {
        //Get Claim
        if (empty($this->claim)) {
            throw new InvalidTokenException();
        } //End if

        return $this->claim->getUser();
    } //Function ends


    /**
     * Persist token.
     *
     * @return \boolean
     */
    public function storeToken()
    {
        return $this->manager->encode($this->claim)->store();
    } //Function ends

} //Class ends