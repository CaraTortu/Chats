<?php

/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats
*/

namespace Chat;

class ChatConfig {

    // General settings.
    public $server_hostname = "http://127.0.0.1";   // Server hostname. (with http:// || https://)
    public $server_port = "8000";                   // Port in which the server on. (Only set if you are using a port other than 80/443.)

    // Database settings.
    public $db_path = "db/chat.db";                 // Path to the database file. 
    public $db_type = "sqlite";                     // Database type.

    // Mail configuration. (*) means required.
    public $smtp_server = "";                       // SMTP server *
    public $smtp_port = 465;                        // SMTP port *
    public $smtp_auth = true;                       // SMTP authentication *
    public $smtp_username = "";                     // SMTP username
    public $smtp_password = "";                     // SMTP password
    public $smtp_ssl = true;                        // SMTP SSL 
    public $smtp_tls = false;                       // SMTP TLS 
    public $smtp_ehlo = "";                         // SMTP HELO

}