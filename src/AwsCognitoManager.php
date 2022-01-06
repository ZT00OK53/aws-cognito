<?php



namespace Zt\Cognito;

use Zt\Cognito\AwsCognitoToken;
use Zt\Cognito\AwsCognitoClaim;
use Zt\Cognito\Providers\StorageProvider;

use Exception;
use Zt\Cognito\Exceptions\AwsCognitoException;
use Zt\Cognito\Exceptions\TokenBlacklistedException;

class AwsCognitoManager
{
    /**
     * The provider.
     *
     * @var \Zt\Cognito\Providers\StorageProvider
     */
    protected $provider;


    /**
     * The blacklist.
     *
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;


    /**
     * The AWS Cognito token.
     *
     * @var string|null
     */
    protected $token;


    /**
     * The AwsCognito Claim token
     * 
     * @var \Zt\Cognito\AwsCognitoClaim|null
     */
    protected $claim;


    /**
     * Constructor.
     *
     * @param  \Zt\Cognito\Providers\StorageProvider  $provider
     * @param  \Tymon\JWTAuth\Blacklist  $blacklist
     * @param  \Tymon\JWTAuth\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(StorageProvider $provider, $blacklist=null)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
    }


    /**
     * Encode the claim.
     *
     * @return \AwsCognitoManager
     */
    public function encode(AwsCognitoClaim $claim)
    {
        $this->claim = $claim;
        $this->token = $claim->getToken();

        return $this;
    } //Function ends


    /**
     * Decode token.
     *
     * @return \boolean
     */
    public function decode()
    {
        return ($this->claim)?$this->claim:null;
    } //Function ends


    /**
     * Persist token.
     *
     * @return \boolean
     */
    public function store()
    {
        $data = $this->claim->getData();
        $durationInSecs = ($data)?(int) $data['ExpiresIn']:3600;
        $this->provider->add($this->token, json_encode($this->claim), $durationInSecs);

        return true;
    } //Function ends


    /**
     * Get Token from store.
     *
     * @return \AwsCognitoManager
     */
    public function fetch(string $token)
    {
        $this->token = $token;
        $claim = $this->provider->get($token);
        $this->claim = $claim?json_decode($claim, true):null;

        return $this;
    } //Function ends


    /**
     * Release token.
     *
     * @return \AwsCognitoManager
     */
    public function release(string $token)
    {
        $this->provider->destroy($token);

        return $this;
    } //Function ends

} //Class ends