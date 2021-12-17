<?php

namespace App\Controllers;

use App\Models\UserModel;

class Auth extends BaseController
{
    public function index()
    {
        return view('index');
    }
    public function login()
    {
        $session = session();
        $model = new UserModel();
        $usernameOrEmail = $this->request->getVar('username_or_email');
        $password = $this->request->getVar('password');
        $data = $model->where('username', $usernameOrEmail)->orWhere('email', $usernameOrEmail)->first();

        if (!$data) {
            $session->setFlashdata('error_signin', true);
            $session->setFlashdata('msg', 'Email or Username not Found');
            return redirect()->to('/auth');
        }

        $pass = $data['password'];
        if (!password_verify($password, $pass)) {
            $session->setFlashdata('error_signin', true);
            $session->setFlashdata('msg', 'Wrong Password');
            return redirect()->to('/auth');
        }

        $ses_data = [
            'user_id'       => $data['id'],
            'user_username'     => $data['username'],
            'user_email'    => $data['email'],
            'user_name'    => $data['name'],
            'logged_in'     => TRUE,
        ];
        $session->set($ses_data);
        return redirect()->to('/home');
    }

    public function logout()
    {
        $session = session();
        $session->destroy();
        return redirect()->to('/auth');
    }

    public function register()
    {


        $model = new UserModel();
        $rules = [
            'username'   => 'required|min_length[3]|max_length[20]',
            'name'       => 'required|min_length[3]|max_length[20]',
            'email'      => 'required|min_length[6]|max_length[50]|valid_email|is_unique[users.email]',
            'password'   => 'required|min_length[6]|max_length[200]'
        ];
        if ($this->validate($rules)) {
            $data = [
                'username'     => $this->request->getVar('username'),
                'name'     => $this->request->getVar('name'),
                'email'     => $this->request->getVar('email'),
                'password' => password_hash($this->request->getVar('password'), PASSWORD_DEFAULT)
            ];
            $model->insert($data);
            return redirect()->to('/auth');
        } else {
            session()->setFlashdata('error_signup', true);
            session()->setFlashdata('message_error', $this->validator->getErrors());
            return redirect()->to('/auth');
        }
    }
}
