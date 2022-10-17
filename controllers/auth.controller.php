<?php

use Firebase\JWT\JWT;
use \Firebase\JWT\Key;


class AuthController
{

    
   
    public function __construct($params)
{
    $this->method = array_shift($params);
    $this->params = $params;

    $request_body = file_get_contents('php://input');
    $this->body = $request_body ? json_decode($request_body, true) : null;

    $this->action = $this->{$this->method}();
}

public function login(){
    $dbs = new DatabaseService("account");
    $email = filter_var($this->body['login'], FILTER_SANITIZE_EMAIL);  //nettoi la donnée passée en 1er param
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {   // verifie que c'est un mail
        return ["result" => false];
    } 
    $accounts = $dbs->selectWhere("login = ? AND is_deleted = ?", [$email, 0]);  //login=email    deleted=0
    $prefix = $_ENV['config']->hash->prefix;
    if(count($accounts) == 1
       && password_verify($this->body['password'], $prefix . $accounts[0]->password)){
       $dbs = new DatabaseService("appUser");
       $appUser = $dbs->selectOne($accounts[0]->Id_appUser);
        
        $secretKey = $_ENV['config']->jwt->secret;  //définie la clé
        $issuedAt = time();                        // durée de conservation du token
        $expireAt = $issuedAt + 60 * 60 *24;        // seconde * minutes * heures
        $serverName = "blog.api";                   // nom du serveur
        $userRole = $appUser->Id_role;
        $userId =  $appUser->Id_appUser;
        $requestData = [
            'iat'  => $issuedAt,
            'iss'  => $serverName,
            'nbf'  => $issuedAt,
            'exp'  => $expireAt,
            'userRole' => $userRole,
            'userId' => $userId
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
public function register(){
    $dbs = new DatabaseService("account");
    $accounts = $dbs->selectWhere("login = ?", [$this->body['email']]);
    if(count($accounts) > 0){
        return ['result'=>false, 'message'=>'email '.$this->body['email'].' already used'];
    }
    $dbs = new DatabaseService("appUser");
    $users = $dbs->selectWhere("pseudo = ?", [$this->body['pseudo']]);
    if(count($users) > 0){
        return ['result'=>false, 'message'=>'pseudo '.$this->body['pseudo'].' already used'];
    }

    $secretKey = $_ENV['config']->jwt->secret;
    $issuedAt = time();
    $expireAt = $issuedAt + 60 * 60 * 1;
    $serverName = "blog.api";
    $pseudo = $this->body['pseudo'];
    $login =  $this->body['email'];
    $requestData = [
        'iat'  => $issuedAt,
        'iss'  => $serverName,
        'nbf'  => $issuedAt,
        'exp'  => $expireAt,
        'pseudo' => $pseudo,
        'login' => $login
    ];
    $token = JWT::encode($requestData, $secretKey, 'HS512');
    
    $href = "http://localhost:3000/account/validate/$token";

    $ms = new MailerService();
    $mailParams = [
        "fromAddress" => ["register@monblog.com","nouveau compte monblog.com"],
        "destAddresses" => [$login],
        "replyAddress" => ["noreply@monblog.com", "No Reply"],
        "subject" => "Créer votre compte nomblog.com",
        "body" => 'Click to validate the account creation <br>
                    <a href="'.$href.'">Valider</a> ',
        "altBody" => "Go to $href to validate the account creation"
    ];
    $sent = $ms->send($mailParams);
    return ['result'=>$sent['result'], 'message'=> $sent['result'] ?
        "Vérifier votre boîte mail et confirmer la création de votre compte sur monblog.com" :
        "Une erreur est survenue, veuiller recommencer l'inscription"];
}

public function validate(){
    $token = $this->body['token'] ?? "";
        
    if(isset($token) && !empty($token)){
        $secretKey = $_ENV['config']->jwt->secret;
        try{
            $payload = JWT::decode($token, new Key($secretKey, 'HS512'));
        }catch(Exception $e){
            $payload = null;
        }
        if (isset($payload) &&
                $payload->iss === "blog.api" &&
                $payload->nbf < time() &&
                $payload->exp > time())
        {
            $pseudo = $payload->pseudo;
            $login =  $payload->login;
            return ["result"=>true, "pseudo"=>$pseudo, "login"=>$login];
        }
    }
    return ['result'=>false];
}


}