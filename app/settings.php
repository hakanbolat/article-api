<?php
declare(strict_types=1);

use DI\ContainerBuilder;
use Monolog\Logger;

return function (ContainerBuilder $containerBuilder) {
    // Global Settings Object
    $containerBuilder->addDefinitions([
        'settings' => [
            'displayErrorDetails' => false, // Should be set to false in production
            'logger' => [
                'name' => 'slim-app',
                'path' => isset($_ENV['docker']) ? 'php://stdout' : __DIR__ . '/../logs/app.log',
                'level' => Logger::DEBUG,
            ],
            'secret_key' => '!#aRticLeApI#!',
            'dsn' => 'host=lepp-postgres port=5432 dbname=example_db user=example_user password=example_pass',
            'twig' => [
                // Template paths
                'paths' => [
                    __DIR__ . '/../templates',
                ],
                // Twig environment options
                'options' => [
                    // Should be set to true in production
                    'cache_enabled' => false,
                    'cache_path' => __DIR__ . '/../tmp/twig',
                ],
            ]
        ],
    ]);
};
