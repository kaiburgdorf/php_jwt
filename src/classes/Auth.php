<?php


class Auth {

    private $_db;
    private $_jwt;

    public function __construct() {
        $this->_db = new Db();
        $this->_jwt = new Jwt();
    }

    public function login($username, $password) {
        $uid = $this->validate_credentials($username, $password);
        if (!$uid) {
            return false;
        }

        $this->_jwt->set_payload($uid, $username, true, 300);
        $jwt = $this->_jwt->generate_jwt();

        header("AuthToken: $jwt");
        header('Access-Control-Expose-Headers: AuthToken');
    
        return true;
    }

    public function register($username, $email, $password) {
        $user_store = $this->_db->getStore('user');
        if ($user_store->findOneBy(["username", "=", $username])) {
            return false;
        }
        $user = [
        "username" => $username,
        "email" => $email,
        "password" => $password
        ];
    
        $user_store->insert($user);
        return true;
    }

    private function validate_credentials($username, $password) {
        $db_user = $this->_db->getStore('user')->findOneBy(["username", "=", $username]);
        if (isset($db_user)) {
            if (strcmp($db_user['password'], $password) === 0) {
                return $db_user['_id'];
            }
        }
        return false;
    }
}

?>