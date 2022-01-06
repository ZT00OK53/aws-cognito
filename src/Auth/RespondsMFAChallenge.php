<?php


namespace Zt\Cognito\Auth;

use App\Models\User;
use Aws\Result as AWSResult;
use Zt\Cognito\AwsCognito;
use Zt\Cognito\AwsCognitoClaim;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;

use Zt\Cognito\AwsCognitoClient;

use Exception;
use Illuminate\Validation\ValidationException;
use Zt\Cognito\Exceptions\InvalidUserFieldException;
use Zt\Cognito\Exceptions\AwsCognitoException;

trait RespondsMFAChallenge
{
    /**
     * The AwsCognito instance.
     *
     * @var \Zt\Cognito\AwsCognito
     */
    protected $cognito;


    /**
     * RespondsMFAChallenge constructor.
     *
     * @param AwsCognito $cognito
     */
    public function __construct(AwsCognito $cognito) {
        $this->cognito = $cognito;
    }

    /**
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws ValidationException
     */
    public function respondMFAChallenge($request)
    {
        if ($request instanceof Request) {
            $validator = Validator::make($request->all(), $this->rules());

            if ($validator->fails()) {
                throw new ValidationException($validator);
            }

            $request = collect($request->all());
        }

        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);

        //Responds MFA challenge
        $result = $client->respondMFAChallenge($request['session'], $request['value'], $request['email']);

        if (is_string($result)) {
            return $response = response()->json(['error' => 'cognito.'.$result], 400);
        } else if ($result instanceof AWSResult) {
            $user = User::where('email', $request['email'])->first();
            $claim = new AwsCognitoClaim($result, $user, 'email');
            $this->cognito->setClaim($claim)->storeToken();
            return $result['AuthenticationResult'];
        }

        return $result;
    }

    /**
     * Get the respond to MFA challenge validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'session'    => 'required',
            'value'      => 'required|string',
            'email'      => 'required|email',
        ];
    }
}
