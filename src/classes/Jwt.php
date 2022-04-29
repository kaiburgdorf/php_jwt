<?php


class Jwt {

    private $_token;
    private $_headers = array('alg'=>'HS256','typ'=>'JWT');
    private $_payload;
    private $_secret;

    function __construct() {
        $this->_token = (isset(getallheaders()['Authorization'])) ?
          getallheaders()['Authorization'] :
          null;
    }





    /**
     * Encodes first parameter with base 64
     * 
     * @param $str String to be encoded
     * 
     * @return base64 encodeter string
     */
    static function base64url_encode($str)
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }



    public function set_header($alg, $typ = 'JWT') {
        $this->_header = array('alg'=>$alg,'typ'=> $typ);
    }

    function set_payload($sub, $name, $admin, $exp) {
        $this->_payload = array(    
            'sub'    => $sub,
            'name'    => $name,
            'admin'    => $admin,
            'iat'    => time(), 
            'exp'    => (time() + $exp)
        );
    }


    function generate_jwt($secret = 'secret')
    {
        $headers_encoded = $this->base64url_encode(json_encode($this->_headers));
        
        $payload_encoded = $this->base64url_encode(json_encode($this->_payload));
        
        $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
        $signature_encoded = $this->base64url_encode($signature);
        
        
        $token = "$headers_encoded.$payload_encoded.$signature_encoded";
        $this->_token = $token;
        return $token;
    }





    function is_jwt_valid($jwt, $secret = 'secret')
    {
        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = $this->base64_decode($tokenParts[0]);
        $payload = $this->base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        global $uid;
        $uid = json_decode($payload)->sub;

        //@TODO fix, alway causes error
        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        // build a signature based on the header and payload using the secret
        $base64_url_header = $this->base64url_encode($header);
        $base64_url_payload = $this->base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
        $base64_url_signature = $this->base64url_encode($signature);

        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64_url_signature === $signature_provided);
        
        if ($is_token_expired || !$is_signature_valid) {
            return false;
        } else {
            return true;
        }
    }

    private function refreshToken() {
        $tokenParts = explode('.', $jwt);
        $token_header = json_decode(base64_decode($tokenParts[0]));
        $token_payload = json_decode(base64_decode($tokenParts[1]));    
        $token_payload->iat = time();
        $token_payload->exp = (time() + 300);
        $jwt = generate_jwt($token_header, $token_payload);
        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    }
}


?>