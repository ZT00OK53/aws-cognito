<?php


namespace Zt\Cognito\Validators;

use Zt\Cognito\Exceptions\InvalidTokenException;

class AwsCognitoTokenValidator
{
    /**
     * Check the structure of the token.
     *
     * @param  string  $value
     *
     * @return string
     */
    public function check($value)
    {
        return $this->validateStructure($value);
    }

    /**
     * @param  string  $token
     *
     * @throws \Zt\Cognito\Exceptions\InvalidTokenException
     *
     * @return string
     */
    protected function validateStructure($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Wrong number of segments');
        } //End if

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new InvalidTokenException('Malformed token');
        }

        return $token;
    } //Function ends

} //Class ends