<?php

use Firebase\JWT\JWT;
use \Firebase\JWT\Key;


class AuthController
{
    public function __construct($params)
    {
        $this->methode = array_shift($params);
        $this->action = null;

        if(!isset($this->methode) ){
            return $this;
        }
        
        $request_body = file_get_contents('php://input');
        $this->body = $request_body ? json_decode($request_body, true) : null;

        $this->table = "account";
        
        if($_SERVER['REQUEST_METHOD'] == "POST"){
            $this->action = $this->login();
        }

        if($_SERVER['REQUEST_METHOD'] == "GET"){
            $this->action = $this->check();
        }
}
public function login()
{
    $email = filter_var($this->body['login'], FILTER_SANITIZE_EMAIL);
    $password = $this->body['password'];
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ["result" => false];
    }
    $dbs = new DatabaseService($this->table);
    $where = "login = ? AND is_deleted = ?";
    $accounts = $dbs->selectWhere($where, [$email, 0]);
    $account = $accounts[0];
    $prefix = $_ENV['config']->hash->prefix;
    if(count($accounts) == 1
       && password_verify($this->body['password'], $prefix . $accounts[0]->password)){
       $dbs = new DatabaseService("appUser");
       $appUser = $dbs->selectOne($account->Id_appUser);
        $secretKey = $_ENV['config']->jwt->secret;  //définie la clé
        $issuedAt = time();                        // durée de conservation du token
        $expireAt = $issuedAt + 60 * 60 *24;        // seconde * minutes * heures
        $serverName = "blog.api";                   // nom du serveur
        $userRole = $appUser->Id_role;
        $userId = $appUser->Id_appUser;
        $requestData = [
            'iat' => $issuedAt,
            'iss' => $serverName,
            'nbf' => $issuedAt,
            'exp' => $expireAt,
            'userRole' => $userRole,
            'userid' => $userId
        ];
        $token = JWT::encode($requestData, $secretKey, 'HS512');

       return ["result" => true, "role" => $appUser->Id_role, "id" => $appUser->Id_appUser, "token" => $token];
    }
    return ["result" => false];
}

public function check(){
    $headers = apache_request_headers();
    if (isset($headers["Authorizations"])) {
        $token = $headers["Authorization"];
    }
    $secretKey = $_ENV['config']->jwt->secret;
    if (isset($token) && !empty($token)) {
        try{
            $payload = JWT::decode($token, new Key($secretKey, 'HS512'));     //HS512 correspond à un algo de hachage plus de plus sécurisé
        }catch(Exception $e){
            $payload = null;
        }
        if (isset($payload) &&
        $payload->iss === "blog.api" &&    //iss doit avoir le meme nom que $serverName
        $payload->nbf < time() &&
        $payload->exp > time())
        {
            return ["result" => true, "role" => $payload->userRole, "id" => $payload->userId];
        }
    }

    return ["result" => false];
}
}