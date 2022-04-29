<?php

class Api {

    private $_methodRestriction = array(
        "login" => ["restriction" => "none"],
        "register" => ["restriction" => "none"],
        "getNoteListData" => ["restriction" => "user"],
        "getEntry" => ["restriction" => "user"],
        'updateNote' => ["restriction" => "user"],
        'newNote' => ["restriction" => "user"],
        'deleteNote' => ["restriction" => "user"]
    );

    // check for enum
    private $_restrictionLevel = array('none' => 0, 'user' => 1, 'admin' => 2);


    private $_method, $_payload_data;
    private $_username, $_password, $_email;

    private $_auth;
    private $_db;
    private $_jwt;
    private $_notes;

    function __construct() {
        //hier GETS und header auslesen
        $this->_username = (isset($_GET['username'])) ? $_GET['username'] : '';
        $this->_password = (isset($_GET['password'])) ? $_GET['password'] : '';
        $this->_email = (isset($_GET['email'])) ? $_GET['email'] : '';
        $this->_method = (isset($_GET['method'])) ? $_GET['method'] : '';
        $this->_payload_data = (isset($_GET['data'])) ? $_GET['data'] : '';
    
        $this->_auth = new Auth();
        $this->_db = new Db();
        $this->_jwt = new Jwt();
        $this->_notes = new Notes();
    }

    public function call_method_from_params() {
        $method = $this->_method;
        $jwt_refresh = false;
        
        //check if method is allowedcallFunction
        if (!$this->_methodRestriction[$method]) {
            return $this->response(false, "Invalid request", "", 500);
        }
        
        $restriction = $this->_methodRestriction[$method];
        $restriction_lvl = $this->_restrictionLevel[$restriction['restriction']];
        //check if method is restricted
        if ($restriction_lvl > 0) {

            $x = getallheaders(); //check isset, not always set
            $this->_jwt->set_token($x['Authorization']);

            $jwt_valid = $this->_jwt->validate_token();
            if (!$jwt_valid) {
                return $this->response(false, "Invalid Token", "", 500);
            }

            $jwt_refresh = true;

            //jwt get role

            // @TODO role neu denken
            $role = 'admin';
            if ($restriction_lvl > $this->_restrictionLevel[$role]) {
                return $this->response(false, "Authorization failed");
            }
        }
        
        $result = call_user_func(array($this, $this->_method));
        if ($jwt_refresh) {
            $this->_jwt->refresh();
        }
        return $result;
    }

    private function response($success = false, $msg = "", $payload = "", $http_code = 200) {
        if ($success) {
            http_response_code(200);
            return json_encode($payload);
        }
        else {
            http_response_code(500);
            return json_encode(array('error_msg' => $msg));
        }

    }

    private function login() {
        $uid = $this->_auth->validate_credentials($this->_username, $this->_password);
        if (!$uid) {
            exit(0);
        }

        $this->_jwt->set_payload($uid, $this->_username, true, 300);
        $jwt = $this->_jwt->generate_jwt();

        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        return $this->response(true, "Successfully logged in", "");
    }
    
    private function register() {
        $user_store = $this->_db->getStore('user');
        if ($user_store->findOneBy(["username", "=", $this->_username])) {
            echo "username already set";
            exit(0);
        }
        $user = [
        "username" => $this->_username,
        "email" => $this->_email,
        "password" => $this->_password
        ];
    
        $result = json_encode($user_store->insert($user));
    
        return $this->response(true, "", $result);
    }

    private function getEntry() {  
        $id = json_decode($this->_payload_data);
        $note = $this->_notes->read($id, 'single');
    
        return $this->response(true, "", $note);
    }


    private function getNoteListData() {                
        $uid = $this->_jwt->get_payload()->sub;
        $notes = $this->_notes->read($uid, 'all');
        
        return $this->response(true, "", $notes);
    }
    
    private function newNote() {
        $note_data = json_decode($this->_payload_data);
        $uid = $this->_jwt->get_payload()->sub;
        $result = $this->_notes->create($uid, $note_data);

        return $this->response(true);
    }

    private function updateNote() {    
        $note_data = json_decode($this->_payload_data);
        $uid = $this->_jwt->get_payload()->sub;
        $result = $this->_notes->update($uid, $note_data);

        return $this->response(true);
    }

    private function deleteNote() {
        $note_id = json_decode($this->_payload_data);
        $this->_notes->delete($note_id);

        return $this->response(true);
    }
}
?>