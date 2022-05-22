<?php

/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats
*/

namespace Chat;

class UrlHandler
{
    // This is the variable that contains the current page content.
    public $rendered;

    // Sets up the handler.
    public function __construct($url, $db)
    {
        $this->url = $url;
        $this->db = $db;
        $this->method = $_SERVER['REQUEST_METHOD'];

        $err = $this->processRequest();
        if ($err) {
            $this->rendered = $err;
            return;
        }

        $this->rendered = $this->classifyAndHandle();
    }

    // Separates arguments and path from url.
    private function processRequest()
    {
        $path = explode('?', $this->url);
        $params = array();

        if ($this->method === 'GET') {
            
            // Separates parameters and values.
            if (count($path) > 1) {
                foreach (explode("&", $path[1]) as $param) {
                    $param = explode('=', $param);
                    $params[$param[0]] = $param[1];
                }
            }
        } elseif ($this->method === 'POST') {
            $params = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== 0) {
                // JSON is not valid
                return "Supply valid JSON";
            }
        } else {
            // Method is not supported.
            return $this->returnError(405);
        }

        // Removes trailing slash.
        if (substr($path[0], -1) == '/') {
            $this->urlBase = substr($path[0], 0, -1);
        } else {
            $this->urlBase = $path[0];
        }

        $this->urlParams = $params;
    }

    // Classifies the url and handles it.
    private function classifyAndHandle()
    {
        $path = explode('/', $this->urlBase);

        if (count($path) > 1 && $path[1] == 'api') {
            if (count($path) <= 2) {
                return $this->returnError(404);
            }
            return $this->handleApi($path[2], $this->urlParams, $this->method);
        } elseif (count($path) > 1 && $path[1] == 'static') {
            if (count($path) <= 2) {
                return $this->returnError(404);
            }
            return $this->handleStatic();
        } else {
            return $this->handleWeb();
        }
    }

    // Handles /api requests.
    private function handleApi($action, $params, $method)
    {
        session_start();
        switch ($action) {
            case 'login':
                if ($method == 'POST') {
                    $username = $params['username'];
                    $password = $params['password'];
                    if ($username == "" || $password == "") {
                        // Username or password is empty.
                        return "Please supply all parameters";
                    }
                    // Check username and password.
                    $r = $this->db->checkUser($username, $password);
                    if ($r !== "success") {
                        return $r;
                    }
                    // Check if user is verified.
                    $v = $this->db->checkVerified($username);
                    if ($v !== "success") {
                        return $v;
                    }
                    // User is logged in.
                    $_SESSION['tmp_user'] = $username;
                    return $r;
                } else {
                    // Method is not POST.
                    return $this->returnAPIError(405);
                }
                break;

            case 'signup':
                if ($method == 'POST') {
                    $username = $params['username'];
                    $password = $params['password'];
                    $email = $params['email'];
                    if ($email == "" || $username == "" || $password == "") {
                        // Username, password or email is empty.
                        return "Please supply all parameters";
                    }
                    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                        // Email is not valid.
                        return "Please enter a valid email";
                    }
                    $r = $this->db->addUser($username, $password, $email);
                    return $r;
                } else {
                    return $this->returnAPIError(405);
                }
                break;
            
            case 'verify':
                if ($method == 'POST') {
                    $username = $params['username'];
                    $token = $params['token'];
                    if ($username == "" || $token == "") {
                        // Username or code is empty.
                        return "Please supply all parameters";
                    }
                    $r = $this->db->verifyUser($username, $token);
                    return $r;
                } else {
                    return $this->returnAPIError(405);
                }
                break;
            
            case 'tfacode':
                if ($method == 'POST') {
                    $code = $params['code'];
                    if ($code == "") {
                        // Code is empty.
                        return "Please supply all parameters";
                    }
                    if (!isset($_SESSION['tmp_user'])) {
                        return "Please login first";
                    }
                    $r = $this->db->verify2faCode($_SESSION['tmp_user'], $code);
                    return $r;
                } else {
                    return $this->returnAPIError(405);
                }
                break;
            
            case 'tfaimage':
                if ($method == 'POST') {
                    if (!isset($_SESSION['tmp_user'])) {
                        // Username is empty.
                        return "Please login first";
                    }
                    if ($this->db->checkQrScanned($_SESSION['tmp_user'])) {
                        return false;
                    }
                    $r = $this->db->get2faImage($_SESSION['tmp_user']);
                    return $r;
                } else {
                    return $this->returnAPIError(405);
                }
                break;
            default:
                return $this->returnAPIError(404);
        }
    }

    // Handles /* requests.
    private function handleWeb()
    {
        session_start();
        switch ($this->urlBase) {
            case '':
                return file_get_contents("views/index.html");
            case '/login':
                return file_get_contents("views/login.html");
            case '/dashboard':
                if (isset($_SESSION['user'])) {
                    // User is logged in.
                    $f = file_get_contents("views/dashboard.html");
                    $f = str_replace("{username}", $_SESSION['user'], $f);
                    return $f;
                } else {
                    // User is not logged in.
                    return $this->returnError(401);
                }
                break;
            case '/logout':
                session_destroy();
                return $this->returnError(401);
            case '/verify':
                if ($this->urlParams == []) {
                    return $this->returnError(404);
                }
                $f = file_get_contents("views/verify.html");
                $f = str_replace("{{user}}", $this->urlParams['username'], $f);
                $f = str_replace("{{token}}", $this->urlParams['token'], $f);
                return $f;
            case '/tfa':
                if (isset($_SESSION['tmp_user'])) {
                    $f = file_get_contents("views/tfa.html");
                    $f = str_replace("{{user}}", $_SESSION['tmp_user'], $f);
                    return $f;
                } else {
                    return $this->returnError(401);
                }
                break;
            default:
                // Return 404 for all other requests.
                return $this->returnError(404);
        }
    }

    // Handles /static requests.
    private function handleStatic()
    {
        $static_path = str_replace("/static", "static", $this->urlBase);
        
        if (file_exists($static_path) && is_file($static_path)) {
            // File exists and its a file.
            $this->returnMIMEType(substr($static_path, -4));
            return file_get_contents($static_path);
        } else {
            // File does not exist or is not a file.
            return $this->returnError(404);
        }
    }

    // Returns file mime type from extension.
    private function returnMIMEType($path)
    {
        switch ($path) {
            case '.css':
                header('Content-Type: text/css');
                break;
            case '.png':
                header('Content-Type: image/png');
                break;
            case '.jpg':
                header('Content-Type: image/jpeg');
                break;
            case '.gif':
                header('Content-Type: image/gif');
                break;
            case '.ico':
                header('Content-Type: image/x-icon');
                break;
            default:
                if (substr($path, -3) == '.js') {
                    header('Content-Type: application/javascript');
                    break;
                }
                header('Content-Type: text/html');
        }
    }

    // Returns api errors based on status code.
    private function returnAPIError($code)
    {
        http_response_code($code);
        
        switch ($code) {
            case 400:
                return json_encode(array('error' => 'Bad Request'));
            case 401:
                return json_encode(array('error' => 'Unauthorized'));
            case 403:
                return json_encode(array('error' => 'Forbidden'));
            case 404:
                return json_encode(array('error' => 'Not Found'));
            case 405:
                return json_encode(array('error' => 'Method Not Allowed'));
            case 500:
                return json_encode(array('error' => 'Internal Server Error'));
        }
    }

    // Returns web errors based on status code.
    private function returnError($code)
    {
        http_response_code($code);

        switch ($code) {
            case 401:
                header("Location: http://" . $_SERVER['HTTP_HOST'] . "/login");
                die();
            default:
                $tmp = str_replace("{ERRORCODE}", $code, file_get_contents("errors/error.html"));
                $tmp = str_replace("{ERRORMESSAGE}", $this->getErrorMessage($code), $tmp);
                return $tmp;
        }
    }

    // Returns web error message based on status code.
    private function getErrorMessage($code)
    {
        switch ($code) {
            case 404:
                return "The page you are looking for might have been removed or had its name changed.";
                break;
            case 500:
                return "The page you were trying to reach is temporarily unavailable.";
                break;
            case 405:
                return "The method you are trying to use is not allowed.";
                break;
            default:
                return "Huh?";
                break;
        }
    }
}
