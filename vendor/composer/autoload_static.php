<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitfaf392f62e7eb7b94a4f68b1315147b7
{
    public static $prefixLengthsPsr4 = array (
        'R' => 
        array (
            'RobThree\\Auth\\' => 14,
        ),
        'P' => 
        array (
            'PHPMailer\\PHPMailer\\' => 20,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'RobThree\\Auth\\' => 
        array (
            0 => __DIR__ . '/..' . '/robthree/twofactorauth/lib',
        ),
        'PHPMailer\\PHPMailer\\' => 
        array (
            0 => __DIR__ . '/..' . '/phpmailer/phpmailer/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitfaf392f62e7eb7b94a4f68b1315147b7::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitfaf392f62e7eb7b94a4f68b1315147b7::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitfaf392f62e7eb7b94a4f68b1315147b7::$classMap;

        }, null, ClassLoader::class);
    }
}
