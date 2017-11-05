<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Created by PhpStorm.
 * User: .SuperNova's
 * Date: 04/11/2017
 * Time: 13:42
 */

require APPPATH . '/libraries/REST_Controller.php';

class Auth extends REST_Controller
{
    function __construct($config = 'rest'){
        parent::__construct($config);
    }

    function index_post(){
        $CI =& get_instance();
        $user_mail = $this->input->post('user_mail');
        $password = $this->input->post('password');

        $canLogin = $this->users_model->canLogin($user_mail);

        if($canLogin == null){
            return $this->response(array('status' => 'fail', 'msg' =>'Username/Email not registered' ),REST_Controller::HTTP_OK);
        }else{
            $db_pass = $canLogin->password;
            $date = new DateTime();
            $tokenData = array(
                'id' => $canLogin->id,
                'username' => $canLogin->username,
                'iat' => $date->getTimestamp(),
                'exp' => $date->getTimestamp() + 60*60*24*7
            );

            if(password_verify($password, $db_pass)){
                return $this->response(array('status' => 'ok', 'token'=> AUTHORIZATION::generateToken($tokenData)),
                    REST_Controller::HTTP_OK);
            }else{
                return $this->response(array('status' => 'fail', 'msg' =>'Wrong Password' ),502);
            }
        }
    }

    //example to check token
    function ex_get(){

        $headers = $this->input->request_headers();
        if (array_key_exists('Authorization', $headers) && !empty($headers['Authorization'])) {
            $token = Authorization::validateToken($headers['Authorization']);
            if ($token != false) {
                $data = array('status' => 'ok' ,'item' => $this->users_model->getItem());
                return $this->response($data, REST_Controller::HTTP_OK);
            }
            $response = [
                'status' => REST_Controller::HTTP_UNAUTHORIZED,
                'message' => 'Unauthorized',
            ];
            $this->response($response, REST_Controller::HTTP_UNAUTHORIZED);
            return;
        }
        $response = [
            'status' => REST_Controller::HTTP_UNAUTHORIZED,
            'message' => 'Unauthorized',
        ];
        $this->response($response, REST_Controller::HTTP_UNAUTHORIZED);
        return;
    
    }
}