<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header('Content-Type: text/html; charset=utf-8');

//prevent script on being executed on OPTIONS requests
if(!strcmp($_SERVER['REQUEST_METHOD'], "OPTIONS")) {
	echo "yes, backend is right there 4 u :)";
	exit(0);
}



require_once __DIR__ . "/lib/SleekDB-master/src/Store.php";

$databaseDirectory = dirname(__FILE__) . "/db";

$method = (isset($_GET['method'])) ? $_GET['method'] : 'register';
$username = (isset($_GET['username'])) ? $_GET['username'] : '';
$password = (isset($_GET['password'])) ? $_GET['password'] : '';
$email = (isset($_GET['email'])) ? $_GET['email'] : '';
$payload_data = (isset($_GET['data'])) ? $_GET['data'] : "";
$uid = null;




if(!strcmp($method, "login")) {
    if(!validate_credentials($username, $password)) {
        echo "login failed";
        exit(0);
    }

	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);

	$db_user = $newStore->findOneBy(["username", "=", $username]);

    $headers = array('alg'=>'HS256','typ'=>'JWT');
    $payload = array(	
						'sub'	=> $db_user['_id'],
						'name'	=> $username,
						'admin'	=> true,
						'iat'	=> time(), 
						'exp'	=> (time() + 3000)
					);

    $jwt = generate_jwt($headers, $payload);

    echo $jwt;
}



if(!strcmp($method, "register")) {
	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false, 'primary_key' => "_id"]);

	if($newStore->findOneBy(["username", "=", $username])) {
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



if(!strcmp($method, "getServerTime")) {
	$apache_headers = getallheaders();
	$auth_header = $apache_headers['Authorization'];
	if(!is_jwt_valid($auth_header)) {
		echo "please login, use token: " . $auth_header;
		exit(0);
	}

	echo "servertime: " . time();
}



if(!strcmp($method, "getAllUsers")) {
	$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);

	echo json_encode($newStore->findBy(["username", "=", $username]));
}


if(!strcmp($method, "getEntry")) {
	$newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false]);

	$id = json_decode($payload_data);
	$note = $newStore->findOneBy( ["_id", "=", $id] );
	echo json_encode($note);
}


if(!strcmp($method, "getNoteListData")) {
	//$newStore = new \SleekDB\Store("user", $databaseDirectory, ["timeout" => false]);

	$apache_headers = getallheaders();
	$auth_header = $apache_headers['Authorization'];
	if(!is_jwt_valid($auth_header)) {
		echo "please login, use token: " . $auth_header;
		exit(0);
	}

	$newStore = new \SleekDB\Store("notes", $databaseDirectory, ["timeout" => false]);

	$notes = $newStore->findBy(["uid", "=", $uid]);
	$note_list_data = array();
	foreach ($notes as $note) {
		$note_list_entry = array(	"title" => $note['title'],
									"teaser" => (str_split($note['content'],40)[0]),
									"last_change" => $note['last_change'],
									"id" => $note['_id']
								);
		array_push($note_list_data, $note_list_entry);
	}


	echo json_encode($note_list_data);
}


if(!strcmp($method, "newNote")) {

	$apache_headers = getallheaders();
	$auth_header = $apache_headers['Authorization'];
	if(!is_jwt_valid($auth_header)) {
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

if(!strcmp($method, "updateNote")) {

	$apache_headers = getallheaders();
	$auth_header = $apache_headers['Authorization'];
	if(!is_jwt_valid($auth_header)) {
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




function validate_credentials($username, $password) {
	global $databaseDirectory;
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

	global $uid;
	$uid = json_decode($payload)->sub;

	//@TODO fix, alway causes error
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

?>
