<?php

namespace Controllers;

use Classes\Email;  
use Model\Usuario;
use MVC\Router;

class LoginController {
    public static function login(Router $router) {
        $alertas = [];

        $auth = new Usuario;

        if($_SERVER['REQUEST_METHOD'] === 'POST') {
            $auth = new Usuario($_POST);

            $alertas = $auth->validarLogin();

            if(empty($alertas)) {
                // Revisar si el usuario existe
                $usuario = Usuario::where('email', $auth->email);

                if($usuario) {
                    // Verificar si el password es correcto
                    if($usuario->comprobarPasswordAndVerificado($auth->password)) {
                    // Autenticar el usuario
                    session_start();
                    
                    $_SESSION['id'] = $usuario->id;

                    $_SESSION['nombre'] = $usuario->nombre . " " . $usuario->apellido;

                    $_SESSION['email'] = $usuario->email;

                    $_SESSION['login'] = true;

                    // Redireccionar
                    if($usuario->admin === "1") {
                        $_SESSION['admin'] = $usuario->admin ?? null;
                        header('Location: /admin');
                    } else {
                        header('Location: /cita');
                    } 


                    }
                } else {
                    Usuario::setAlerta('error', 'El usuario no existe');
                }
            }
        }
        
        $alertas = Usuario::getAlertas();

        $router->render('auth/login', [
            'alertas' => $alertas,
            'auth' => $auth
        ]);
    }

    public static function logout() {
        if(!isset($_SESSION)) {
            session_start();
        }

        $_SESSION = [];

        header('Location: /');
    }

    public static function olvide(Router $router) {

        $alertas = [];

        if($_SERVER['REQUEST_METHOD'] === 'POST') {
            $auth = new Usuario($_POST);
            $alertas = $auth->validarEmail();

            if(empty($alertas)) {
                $usuario = Usuario::where('email', $auth->email);

                if($usuario && $usuario->confirmado === "1") {

                    // Generar un token
                    $usuario->crearToken();
                    $usuario->guardar();

                    // Enviar un email de recuperación
                    $email = new Email($usuario->email, $usuario->nombre, $usuario->token);
                    $email->enviarInstrucciones();


                    // Alerta de exito
                    Usuario::setAlerta('exito', 'Revisa tu email para cambiar tu password');
                } else {
                    Usuario::setAlerta('error', 'El usuario no existe o no ha sido confirmado');
                    
                }
            }
        }
        
        $alertas = Usuario::getAlertas();

        $router->render('auth/olvide-password', [
            'alertas' => $alertas
        ]);
        
    }

    public static function recuperar(Router $router) {

        $alertas = [];
        $error = false;

        $token = s($_GET['token']);

        // Buscar el usuario por el token
        $usuario = Usuario::where('token', $token);

        if(empty($usuario)) {
            Usuario::setAlerta('error', 'Token no valido');
            $error = true;
        }

        if($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Leer el nuevo password
            $password = new Usuario($_POST);
            $alertas = $password->validarPassword();

            if(empty($alertas)) {
                $usuario->password = null;

                $usuario->password = $password->password;
                $usuario->hashPassword();
                $usuario->token = null;

                $resultado = $usuario->guardar();
                if($resultado) {
                    header('Location: /');
                }
            }
        }
            

        $alertas = Usuario::getAlertas();
        $router->render('auth/recuperar-password', [
            'alertas' => $alertas,
            'error' => $error
        ]);    
    }

    public static function crear(Router $router) {

         $usuario = new Usuario;

         // Alertas vacias
        $alertas = [];

        if($_SERVER['REQUEST_METHOD'] === 'POST') {

           $usuario->sincronizar($_POST);
           $alertas = $usuario->validarNuevaCuenta();

            // Revisar que alertas esten vacias
            if(empty($alertas)) {
                // Verificar si el usuario ya existe
                $resultado = $usuario->existeUsuario();

                if($resultado->num_rows) {
                    $alertas = Usuario::getAlertas();

                } else {

                    // Hashear el password
                    $usuario->hashPassword();

                    // Generar un token
                    $usuario->crearToken();

                    // Enviar un email de confirmación
                    $email = new Email($usuario->nombre, $usuario->email, $usuario->token);

                    $email->enviarConfirmacion();

                    // Crear el usuario
                    $resultado = $usuario->guardar();
                    if($resultado) {
                        // Redireccionar
                        header('Location: /mensaje');
                    }

                    // debuguear($usuario);

                }
            } 

        }
        $router->render('auth/crear-cuenta', [
            'usuario' => $usuario,
            'alertas' => $alertas
        ]);
    
    }

    public static function mensaje(Router $router) {
       $router->render('auth/mensaje');
    }

    public static function confirmar(Router $router) {
        $alertas = [];

        $token = s($_GET['token']);

        $usuario = Usuario::where('token', $token);

        if(empty($usuario)) {
            // Mostar error
            Usuario::setAlerta('error', 'Token no valido');
        } else {
            // modificar el usuario
            $usuario->confirmado = "1";
            $usuario->token = null;
            $usuario->guardar();
            Usuario::setAlerta('exito', 'Cuenta confirmada');
        }

        // Obtener alertas
        $alertas = Usuario::getAlertas();

        // Renderizar la vista
        $router->render('auth/confirmar-cuenta', [
            'alertas' => $alertas
        ]);
    }   
}    