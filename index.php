<?php

/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats
*/

namespace Chat;

use PDO;

require 'Router.php';
require 'Database.php';
require 'Config.php';
require 'vendor/autoload.php';

$config = new ChatConfig();
$db = new PDO($config->db_type.':'.$config->db_path);
$database = new Database($db, $config);

$req = $_SERVER['REQUEST_URI'];

$handler = new UrlHandler($req, $database);

// Renders the page.
echo $handler->rendered;