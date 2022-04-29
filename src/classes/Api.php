<?php
/* header("Access-Control-Allow-Origin: *");

//prevent script on being executed on OPTIONS requests
if (!strcmp($_SERVER['REQUEST_METHOD'], "OPTIONS")) {
    echo "yes, backend is right there 4 u :)";
    exit(0);
}
 */
class Api {

    private $_methodRestriction = array(
        "login" => ["restriction" => "none"],
        "getEntry" => ["restriction" => "user"]
    );

    // check for enum
    private $_restrictionLevel = array('none' => 0, 'user' => 1, 'admin' => 2);


    private $_method, $_payload_data;
    private $_username, $_password, $_email;

    private $_auth;
    private $_db;
    private $_jwt;

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
    }

    public function call_method_from_params() {
        $method = $this->_method;
        
        //check if method is allowedcallFunction
        if (!$this->_methodRestriction[$method]) {
            return $this->response(false, "Invalid request");
        }
        
        $restriction = $this->_methodRestriction[$method]['restriction'];
        
        //check if method is restricted
        if ($restriction > 0) {
            //jwt get role
            $role = 'admin';
            if ($this->_restrictionLevel[$restriction] > $this->_restrictionLevel[$role]) {
                return $this->response(false, "Authorization failed");
            }
        }
        return $this->login();
        //return  call_user_func($this->_method);
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
        if (!$this->_auth->validate_credentials($this->_username, $this->_password)) {
            echo "login failed";
            exit(0);
        }
    
        $db_user = $this->_db->getStore('user')->findOneBy(["username", "=", $username]);
    
        $this->_jwt->set_payload('1', $username, true, 300);
        $jwt = $this->_jwt->generate_jwt();

        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        return $this->response(true, "Successfully logged in", "");
    }
}

    /*
    private function register() {
        $newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        if ($newStore->findOneBy(["username", "=", $username])) {
            echo "username already set";
            exit(0);
        }
        $user = [
        "username" => $username,
        "email" => $email,
        "password" => $password
        ];
    
        $result = json_encode($newStore->insert($user));
    
        echo "result: $result";
    }

    private function getEntry() {
        $apache_headers = getallheaders();
        $jwt = $apache_headers['Authorization'];
        if (!is_jwt_valid($jwt)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store(
            "notes", $databaseDirectory, ["timeout" => false]
        );
        $id = json_decode($payload_data);
        $note = $newStore->findOneBy(["_id", "=", $id]);
    
        $tokenParts = explode('.', $jwt);
        $token_header = json_decode(base64_decode($tokenParts[0]));
        $token_payload = json_decode(base64_decode($tokenParts[1]));    
        $token_payload->iat = time();
        $token_payload->exp = (time() + 300);
        $jwt = generate_jwt($token_header, $token_payload);
        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        echo json_encode($note);
    }


    private function getNoteListData() {
        if (!strcmp($method, "getNoteListData")) {
            //$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);
        
            $apache_headers = getallheaders();
            $auth_header = $apache_headers['Authorization'];
            if (!is_jwt_valid($auth_header)) {
                echo "please login, use token: " . $auth_header;
                exit(0);
            }
        
            $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false]);
        
            $notes = $newStore->findBy(["uid", "=", $uid]);
            $note_list_data = array();
            foreach ($notes as $note) {
                $note_list_entry = array(    "title" => $note['title'],
                                            "teaser" => (str_split($note['content'], 40)[0]),
                                            "last_change" => $note['last_change'],
                                            "id" => $note['_id']
                                        );
                array_push($note_list_data, $note_list_entry);
            }
        
        
            echo json_encode($note_list_data);
        }
    }

    private function newNote() {
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_data = json_decode($payload_data);
    
        $note = [
        "uid" => $uid,
        "last_change" => time(),
        "title" => $note_data->title,
        "content" => $note_data->content
        ];
    
        $result = json_encode($newStore->insert($note));
    
        echo "result: $result";
    }

    private function updateNote() {
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_data = json_decode($payload_data);
    
        $note = [
        "uid" => $uid,
        "last_change" => time(),
        "title" => $note_data->title,
        "content" => $note_data->content,
        "_id" => $note_data->id
        ];
    
        $result = json_encode($newStore->updateOrInsert($note));
    
        echo "result: $result";
    }

    private function deleteNote() {
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_id = json_decode($payload_data);
    
    
        $result = json_encode($newStore->deleteBy(['_id', '=', $note_id]));
    
        echo "result: $result";
    }





    if (!strcmp($method, "login")) {
        if (!validate_credentials($username, $password)) {
            echo "login failed";
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);
    
        $db_user = $newStore->findOneBy(["username", "=", $username]);
    
        $headers = array('alg'=>'HS256','typ'=>'JWT');
        $payload = array(    
                            'sub'    => $db_user['_id'],
                            'name'    => $username,
                            'admin'    => true,
                            'iat'    => time(), 
                            'exp'    => (time() + 300)
                        );
    
        $jwt = generate_jwt($headers, $payload);

        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        echo $jwt;
    }
    
    
    
    if (!strcmp($method, "register")) {
        $newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        if ($newStore->findOneBy(["username", "=", $username])) {
            echo "username already set";
            exit(0);
        }
        $user = [
        "username" => $username,
        "email" => $email,
        "password" => $password
        ];
    
        $result = json_encode($newStore->insert($user));
    
        echo "result: $result";
    }
    
    
    
    if (!strcmp($method, "getServerTime")) {
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        echo "servertime: " . time();
    }
    
    
    
    if (!strcmp($method, "getAllUsers")) {
        $newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);
    
        echo json_encode($newStore->findBy(["username", "=", $username]));
    }
    
    
    if (!strcmp($method, "getEntry")) {
        $apache_headers = getallheaders();
        $jwt = $apache_headers['Authorization'];
        if (!is_jwt_valid($jwt)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store(
            "notes", $databaseDirectory, ["timeout" => false]
        );
        $id = json_decode($payload_data);
        $note = $newStore->findOneBy(["_id", "=", $id]);
    
        $tokenParts = explode('.', $jwt);
        $token_header = json_decode(base64_decode($tokenParts[0]));
        $token_payload = json_decode(base64_decode($tokenParts[1]));    
        $token_payload->iat = time();
        $token_payload->exp = (time() + 300);
        $jwt = generate_jwt($token_header, $token_payload);
        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        echo json_encode($note);
    }
    
    
    if (!strcmp($method, "getNoteListData")) {
        //$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);
    
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false]);
    
        $notes = $newStore->findBy(["uid", "=", $uid]);
        $note_list_data = array();
        foreach ($notes as $note) {
            $note_list_entry = array(    "title" => $note['title'],
                                        "teaser" => (str_split($note['content'], 40)[0]),
                                        "last_change" => $note['last_change'],
                                        "id" => $note['_id']
                                    );
            array_push($note_list_data, $note_list_entry);
        }
    
    
        echo json_encode($note_list_data);
    }
    
    
    if (!strcmp($method, "newNote")) {
    
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_data = json_decode($payload_data);
    
        $note = [
        "uid" => $uid,
        "last_change" => time(),
        "title" => $note_data->title,
        "content" => $note_data->content
        ];
    
        $result = json_encode($newStore->insert($note));
    
        echo "result: $result";
    }
    
    if (!strcmp($method, "updateNote")) {
    
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_data = json_decode($payload_data);
    
        $note = [
        "uid" => $uid,
        "last_change" => time(),
        "title" => $note_data->title,
        "content" => $note_data->content,
        "_id" => $note_data->id
        ];
    
        $result = json_encode($newStore->updateOrInsert($note));
    
        echo "result: $result";
    }
    
    
    if (!strcmp($method, "deleteNote")) {
    
        $apache_headers = getallheaders();
        $auth_header = $apache_headers['Authorization'];
        if (!is_jwt_valid($auth_header)) {
            echo "please login, use token: " . $auth_header;
            exit(0);
        }
    
        $newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);
    
        $note_id = json_decode($payload_data);
    
    
        $result = json_encode($newStore->deleteBy(['_id', '=', $note_id]));
    
        echo "result: $result";
    }

}
*/
?>