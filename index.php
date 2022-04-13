<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header('Content-Type: text/html; charset=utf-8');

require_once __DIR__ . "/lib/SleekDB-master/src/Store.php";

#valid credentials
$users = array(
    "testuser" => "pw",
    "demouser" => "passwd"
    );


$method = (isset($_GET['method'])) ? $_GET['method'] : 'register';
$username = (isset($_GET['username'])) ? $_GET['username'] : '';
$password = (isset($_GET['password'])) ? $_GET['password'] : '';
$email = (isset($_GET['email'])) ? $_GET['email'] : '';
$apache_headers = getallheaders() || [];


if(!strcmp($method, "login")) {
    if(!validate_credentials($username, $password, $users)) {
        echo "login failed";
        exit(0);
    }
    $headers = array('alg'=>'HS256','typ'=>'JWT');
    $payload = array('user'=>'420','name'=>$username, 'admin'=>true, 'exp'=>(time() + 60));

    $jwt = generate_jwt($headers, $payload);

    echo $jwt;
}







if(!strcmp($method, "register")) {
	$databaseDirectory = "./db";
	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);

	$user = [
		"username" => $username,
		"email" => $email,
		"password" => $password
	];

	$result = json_encode($newStore->insert($user));

	echo "result: $result";
}


if(!strcmp($method, "getServerTime")) {
	global $apache_headers;
	if(!is_jwt_valid($apache_headers['Authorization'])) {
		echo "please login, use token: " . $apache_headers['Authorization'];
		exit(0);
	}

	echo "servertime: " . time();
}




if(!strcmp($method, "getAllUsers")) {
	$databaseDirectory = "./db";
	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);

	echo json_encode($newStore->findBy(["username", "=", $username]));
}






function validate_credentials($username, $password, $users) {
	$databaseDirectory = "./db";
	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);

	$db_user = $newStore->findOneBy(["username", "=", $username]);
    if(isset($db_user)) {
        if(strcmp($db_user['password'], $password) === 0) {
            return true;
        }
    }
    return false;
}

function base64url_encode($str) {
    return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
}

function generate_jwt($headers, $payload, $secret = 'secret') {
	$headers_encoded = base64url_encode(json_encode($headers));
	
	$payload_encoded = base64url_encode(json_encode($payload));
	
	$signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
	$signature_encoded = base64url_encode($signature);
	
	$jwt = "$headers_encoded.$payload_encoded.$signature_encoded";
	
	return json_encode(array("method" => "login", "jwt" => $jwt));
}

function is_jwt_valid($jwt, $secret = 'secret') {
	// split the jwt
	$tokenParts = explode('.', $jwt);
	$header = base64_decode($tokenParts[0]);
	$payload = base64_decode($tokenParts[1]);
	$signature_provided = $tokenParts[2];

	// check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
	$expiration = json_decode($payload)->exp;
	$is_token_expired = ($expiration - time()) < 0;

	// build a signature based on the header and payload using the secret
	$base64_url_header = base64url_encode($header);
	$base64_url_payload = base64url_encode($payload);
	$signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
	$base64_url_signature = base64url_encode($signature);

	// verify it matches the signature provided in the jwt
	$is_signature_valid = ($base64_url_signature === $signature_provided);
	
	if ($is_token_expired || !$is_signature_valid) {
		return FALSE;
	} else {
		return TRUE;
	}
}
#if method is signup
#


?>
