<?php


class Jwt {

    private $_token;
    private $_headers = array('alg'=>'HS256','typ'=>'JWT');
    private $_payload;
    private $_secret;

    function __construct($token = null) {
        if ($token) {
                $this->_token = $token;
                $this->_payload = json_decode(base64_decode(
                    explode(".", $token)[1]
                ));
            //$this->validate_token(); // to set header and payload from token
        }
    }



    function set_token($token) {
    }



    /**
     * Encodes first parameter with base 64
     * 
     * @param $str String to be encoded
     * 
     * @return base64 encodeter string
     */
    function base64url_encode($str)
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }



    public function set_header($alg, $typ = 'JWT') {
        $this->_headers = array('alg'=>$alg,'typ'=> $typ);
    }

    function set_payload($sub, $name, $admin, $exp) {
        $this->_payload = (object) [    
            'sub'    => $sub,
            'name'    => $name,
            'admin'    => $admin,
            'iat'    => time(), 
            'exp'    => (time() + $exp)
        ];
    }

    function get_payload() {
        $this->validate_token();
        return $this->_payload;
    }


    function generate_jwt($secret = 'secret')
    {
        $headers_encoded = $this->base64url_encode(json_encode($this->_headers));
        
        $payload_encoded = $this->base64url_encode(json_encode($this->_payload));
        
        $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", "secret", true);
        $signature_encoded = $this->base64url_encode($signature);
        
        
        $token = "$headers_encoded.$payload_encoded.$signature_encoded";
        $this->_token = $token;
        return $token;
    }




    /**
     * @TODO umstrukturieren, erst signiture prügen, dann obj variablen setzen
     */
    function validate_token($secret = 'secret')
    {

        if(!(isset($this->_token))) return false;
        $jwt = $this->_token;

        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        //$this->set_payload(json_decode($payload)->sub, json_decode($payload)->name, json_decode($payload)->admin, 300);
        $this->_header = json_decode($header);

        //@TODO fix, alway causes error
        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = $this->_payload->exp;
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

    public function refresh() {
        $this->validate_token(); // to make sure this token is set correctly
        
        //echo json_encode($this->get_payload());
        //$this->_payload->iat = time();
        //$this->_payload->exp = (time() + 300);
        
        $pl = (array) $this->get_payload();
        $this->set_payload(
            $pl['sub'], $pl['name'], $pl['admin'], 300
        );

        $this->_token = $this->generate_jwt();

        header("AuthToken: $this->_token");
        header('Access-Control-Expose-Headers: AuthToken');
    }
}


?>