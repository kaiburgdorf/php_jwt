<?php


header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . "/../lib/SleekDB-master/src/Store.php";

require __DIR__ . "/../src/classes/Api.php";
require __DIR__ . "/../src/classes/Auth.php";
require __DIR__ . "/../src/classes/Db.php";
require __DIR__ . "/../src/classes/Jwt.php";
require __DIR__ . "/../src/classes/Notes.php";
//require __DIR__ . "/../src/classes/User.php";


$main = new Main();
$main->run();

class Main {

    private $api;

    public function __construct() {
        //$this->api = new Api();
    }

    public function run() {
        //prevent script on being executed on OPTIONS requests
        if (!strcmp($_SERVER['REQUEST_METHOD'], "OPTIONS")) {
            http_response_code(200);
            echo "yes, backend is right there 4 u :)";
            exit(0);
        }
        elseif(!strcmp($_SERVER['REQUEST_METHOD'], "GET")) {
            echo (new Api)->call_method_from_params();
        }
    }
}


?>
