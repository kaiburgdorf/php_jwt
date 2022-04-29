<?php

class Db {

    private $_stores;
    private $_database_directory;

    public function __construct() {
        $this->_database_directory = dirname(__FILE__) . "/../../db"; //get from config
        $this->_stores = [];
    }



    public function getStore($store) {
        if (!isset($this->_stores[$store])) {
            $this->_stores[$store] = new \SleekDB\Store($store, $this->_database_directory, ["timeout" => false, 'primary_key' => "_id"]);
        }
        return $this->_stores[$store];
    }
}
?>