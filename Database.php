<?php
/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats!
*/

namespace Chat;
use PDO;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use RobThree\Auth\TwoFactorAuth;

require 'vendor/autoload.php';

class Database
{
    public function __construct($db, $config)
    {
        $this->db = $db;
        $this->config = $config;
        $this->setup(); // Sets up the database.
    }

    // Sets up the database.
    private function setup()
    {
        // Check if table exists.
        $r = $this->db->prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = 'users';");
        $r->execute();
        if (count($r->fetchAll(PDO::FETCH_ASSOC)) == 0) {
            // Table does not exist, creating.
            shell_exec("sqlite3 db/chat.db < db/SQL/SETUP.sql");
        }
    }

    // Adds a user to the database. (sign up)
    public function addUser($username, $password, $email)
    {
        // Checks password length.
        if (strlen($password) < 8) {
            return "Password must be at least 8 characters long.";
        }
        // Check numbers in password.
        if (!preg_match("#[0-9]+#", $password)) {
            return "Password must contain at least one number.";
        }
        // Check uppercase letters in password.
        if (!preg_match("#[A-Z]+#", $password)) {
            return "Password must contain at least one uppercase letter.";
        }
        // Check lowercase letters in password.
        if (!preg_match("#[a-z]+#", $password)) {
            return "Password must contain at least one lowercase letter.";
        }
        // Check symbols in password
        if (!preg_match('/[-!$%^&*()_+|~=`{}\[\]:";\'<>?,.\/]/', $password)) {
            return "Password must contain at least one symbol.";
        }

        // Check if username is taken.
        $r = $this->db->prepare("SELECT id FROM users WHERE username = :user;");
        $r->bindParam(':user', $username, PDO::PARAM_STR);
        $r->execute();
        if (count($r->fetchAll(PDO::FETCH_ASSOC)) != 0) {
            return "Username is taken";
        }
        
        // Check if email is taken.
        $r = $this->db->prepare("SELECT id FROM users WHERE email = :email;");
        $r->bindParam(':email', $email, PDO::PARAM_STR);
        $r->execute();
        if (count($r->fetchAll(PDO::FETCH_ASSOC)) != 0) {
            return "Email is already used";
        }

        // Creates the account
        $tfa = new TwoFactorAuth('Chats!');
        $password = hash('sha256', $password);
        $token = hash('sha256', rand(0, 1000000000).uniqid().time());
        $twofa_secret = $tfa->createSecret();
        $r = $this->db->prepare("INSERT INTO users (username, password, email, verify_token, twofa_secret, twofa_image) VALUES (:user, :pass, :email, :token, :secret, :image);");
        $r->bindParam(':user', $username, PDO::PARAM_STR);
        $r->bindParam(':pass', $password, PDO::PARAM_STR);
        $r->bindParam(':email', $email, PDO::PARAM_STR);
        $r->bindParam(':token', $token, PDO::PARAM_STR);
        $r->bindParam(':secret', $twofa_secret, PDO::PARAM_STR);
        $r->bindParam(':image', $tfa->getQRCodeImageAsDataUri($username, $twofa_secret), PDO::PARAM_STR);
        $status = $r->execute();
        if (!$status) {
            return "Error adding user";
        }
        
        
        // Verifies that it was added correctly
        $r = $this->db->prepare("SELECT id FROM users WHERE username = :user;");
        $r->bindParam(':user', $username, PDO::PARAM_STR);
        $r->execute();
        if (count($r->fetchAll(PDO::FETCH_ASSOC)) == 0) {
            return "Something went wrong, try again";
        }

        // Sends the verification email
        $r = $this->sendVerificationEmail($username, $token, $email);
        if ($r !== "success") {
            return $r;
        }

        return "success";
    }

    // Checks if the credentials supplied are correct. (log in)
    public function checkUser($username, $password)
    {
        $password = hash('sha256', $password);

        $exec = $this->db->prepare("SELECT id FROM users WHERE username = :user AND password = :pass;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->bindParam(':pass', $password, PDO::PARAM_STR);
        $exec->execute();
        if (count($exec->fetchAll(PDO::FETCH_ASSOC)) == 0) {
            return "Wrong username or password";
        }

        return "success";
    }

    // Checks if the user is verified.
    public function checkVerified($username)
    {
        $exec = $this->db->prepare("SELECT verified FROM users WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        $verified = $exec->fetchAll(PDO::FETCH_ASSOC)[0]['verified'];
        if ($verified == 0) {
            return "Email is not verified, please verify your email first";
        }
        return "success";
    }

    // Verifies the user.
    public function verifyUser($username, $token)
    {
        // Check if user exists.
        $r = $this->db->prepare("SELECT id FROM users WHERE username = :user;");
        $r->bindParam(':user', $username, PDO::PARAM_STR);
        $r->execute();
        if (count($r->fetchAll(PDO::FETCH_ASSOC)) == 0) {
            return "User does not exist";
        }
        
        // Check if token is correct.
        $exec = $this->db->prepare("SELECT verify_token FROM users WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        $verify_token = $exec->fetchAll(PDO::FETCH_ASSOC)[0]['verify_token'];
        if ($verify_token != $token) {
            return "Invalid token";
        }

        $exec = $this->db->prepare("UPDATE users SET verified = 1 WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        return "success";
    }

    // Sends the verification email.
    public function sendVerificationEmail($username, $token, $email)
    {
        $config = $this->config;
        $mail = new PHPMailer(true);

        try {

            //Server settings
            $mail->isSMTP();
            $mail->Host = $config->smtp_server;
            $mail->Port = $config->smtp_port;

            if ($config->smtp_auth) {
                //Enable SMTP authentication
                $mail->SMTPAuth = true;                         
                $mail->Username = $config->smtp_username;  // SMTP username
                $mail->Password = $config->smtp_password;  // SMTP password
            } else {
                //Disable SMTP authentication
                $mail->SMTPAuth = false;
            }

            // Ignore SSL and TLS certificate errors
            $mail->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                ),
                'tls' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                )
            );

            if ($config->smtp_ssl === true && $config->smtp_tls === false) {
                //Enable SSL encryption
                $mail->SMTPSecure = "ssl";

            } elseif ($config->smtp_ssl === false && $config->smtp_tls === true) {
                //Enable TLS encryption.
                $mail->SMTPSecure = "tls";
            }

            if ($config->smtp_ehlo !== ""){
                //Set the SMTP HELO of the message
                $mail->Helo = $config->smtp_ehlo;
            }

            //Recipients
            $mail->setFrom($config->smtp_username, 'Chats! Account verification');
            $mail->addAddress($email, $username);

            // Enable HTML
            $mail->isHTML(true);
            
            //Email subject
            $mail->Subject = 'Chats! Account verification';

            //Email body content from template.
            $f = file_get_contents("views/verify_email.html");
            $f = str_replace("{{user}}", $username, $f);
            $f = str_replace("{{token}}", $token, $f);
            $f = str_replace("{{host}}", $config->server_hostname, $f);
            $f = str_replace("{{port}}", $config->server_port, $f);
            $mail->Body = $f;

            //Send email
            $mail->send();
            return "success";
            
        } catch (Exception $e) {
            return 'Verification mail could not be sent. Try again later.';
        }

    }

    // Verifies 2fa code.
    public function verify2faCode($username, $code)
    {
        $exec = $this->db->prepare("SELECT twofa_secret FROM users WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        $r = $exec->fetchAll(PDO::FETCH_ASSOC);
        if (count($r) == 0) {
            return "User does not exist";
        }

        $secret = $r[0]['twofa_secret'];

        $tfa = new TwoFactorAuth('Chats!');
        $valid = $tfa->verifycode($secret, $code);
        if (empty($valid)) {
            return "Invalid code";
        }
        $_SESSION['user'] = $username;
        return "success";
    }

    // Returns 2fa image.
    public function get2faImage($username)
    {
        $exec = $this->db->prepare("SELECT twofa_image FROM users WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        $r = $exec->fetchAll(PDO::FETCH_ASSOC);
        if (count($r) == 0) {
            return "User does not exist";
        }

        // Set twofa_scanned to 1.
        $exec = $this->db->prepare("UPDATE users SET twofa_scanned = 1 WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        
        return $r[0]['twofa_image'];
    }

    // Checks if qr has already been scanned.
    public function checkQrScanned($username)
    {
        $exec = $this->db->prepare("SELECT twofa_scanned FROM users WHERE username = :user;");
        $exec->bindParam(':user', $username, PDO::PARAM_STR);
        $exec->execute();
        $r = $exec->fetchAll(PDO::FETCH_ASSOC);
        if ($r[0]['twofa_scanned'] == 0) {
            return false;
        }

        return true;
    }
}