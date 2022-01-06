<?php



namespace Zt\Cognito\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

use Zt\Cognito\AwsCognitoClient;

use Exception;
use Zt\Cognito\Exceptions\InvalidUserFieldException;
use Zt\Cognito\Exceptions\AwsCognitoException;

trait RegistersUsers
{

    /**
     * Handle a registration request for the application.
     *
     * @param  \Illuminate\Support\Collection  $request
     * @return \Illuminate\Http\Response
     * @throws InvalidUserFieldException
     */
    public function createCognitoUser(Collection $request, array $clientMetadata=null)
    {
        //Initialize Cognito Attribute array
        $attributes = [];

        //Get the registeration fields
        $userFields = config('cognito.cognito_user_fields');

        //Iterate the fields
        foreach ($userFields as $key => $userField) {
            if ($request->has($userField)) {
                $attributes[$key] = $request->get($userField);
            } else {
                Log::error('RegistersUsers:createCognitoUser:InvalidUserFieldException');
                Log::error("The configured user field {$userField} is not provided in the request.");
                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            } //End if
        } //Loop ends

        //Register the user in Cognito
        $userKey = $request->has('username')?'username':'email';

        //Temporary Password paramter
        $password = $request->has('password')?$request['password']:null;

        return app()->make(AwsCognitoClient::class)->inviteUser($request[$userKey], $password, $attributes, $clientMetadata);
    } //Function ends

} //Trait ends