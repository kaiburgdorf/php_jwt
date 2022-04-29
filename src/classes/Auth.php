<?php


class Auth {

    private $_db;

    public function __construct() {
        $this->_db = new Db();
    }

    public function validate_credentials($username, $password) {
        $db_user = $this->_db->getStore('user')->findOneBy(["username", "=", $username]);
        if (isset($db_user)) {
            if (strcmp($db_user['password'], $password) === 0) {
                return true;
            }
        }
        return false;
    }
}

?>