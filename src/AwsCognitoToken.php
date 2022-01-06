<?php


namespace Zt\Cognito;

use Zt\Cognito\Validators\AwsCognitoTokenValidator;

class AwsCognitoToken
{
    
    /**
     * @var string
     */
    private $token;


    /**
     * Create a new JSON Web Token.
     *
     * @param  string  $token
     *
     * @return void
     */
    public function __construct($token)
    {
        $this->token = (string) (new AwsCognitoTokenValidator)->check($token);
    }


    /**
     * Get the token.
     *
     * @return string
     */
    public function get()
    {
        return $this->token;
    } //Function ends


    /**
     * Get the token when casting to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    } //Function ends

} //Class ends