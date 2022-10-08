l<?php
class AuthController
{
    public function __construct($params)
    {
        $methode = array_shift($params);
        $this->action = null;

        if(!isset($methode) ){
            return $this;
        }
        
        $request_body = file_get_contents('php://input');
        $this->body = $request_body ? json_decode($request_body, true) : null;

        $this->table = "account";
        
        if($_SERVER['REQUEST_METHOD'] == "POST"){
            $this->action = $this->login();
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
    if(isset($account) && password_verify($account->password == $password, $prefix)){
       $dbs = new DatabaseService("appUser");
       $appUser = $dbs->selectOne($account->Id_appUser);
       return ["result" => true, "role" => $appUser->Id_role];
    }
    return ["result" => false];
}
}