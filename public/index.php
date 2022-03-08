<?php
declare(strict_types=1);
error_reporting(E_ALL & ~E_WARNING);
ini_set('date.timezone', 'Europe/Istanbul');
include '../lib/pgsql.php';

use App\Application\Handlers\HttpErrorHandler;
use App\Application\Handlers\ShutdownHandler;
use App\Application\ResponseEmitter\ResponseEmitter;
use DI\ContainerBuilder;
use Slim\Factory\AppFactory;
use Slim\Factory\ServerRequestCreatorFactory;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Pg\Db;
use Slim\Views\Twig;

require __DIR__ . '/../vendor/autoload.php';

// Instantiate PHP-DI ContainerBuilder
$containerBuilder = new ContainerBuilder();

if (false) { // Should be set to true in production
	$containerBuilder->enableCompilation(__DIR__ . '/../var/cache');
}

// Set up settings
if (file_exists(__DIR__ . '/../app/settings.local.php')) {
        $settings = require __DIR__ . '/../app/settings.local.php';
} else {
        $settings = require __DIR__ . '/../app/settings.php';
}
$settings($containerBuilder);

// Set up dependencies
$dependencies = require __DIR__ . '/../app/dependencies.php';
$dependencies($containerBuilder);
// Set up repositories
$repositories = require __DIR__ . '/../app/repositories.php';
$repositories($containerBuilder);

$containerBuilder->addDefinitions([
	ResponseFactoryInterface::class => function (ContainerInterface $container) {
                return $container->get(App::class)->getResponseFactory();
	},
	App::class => function (ContainerInterface $container) {
                AppFactory::setContainer($container);
                return AppFactory::create();
        },
        Twig::class => function (ContainerInterface $container) {
                $settings = $container->get('settings')['twig'];
                $twig = Twig::create($settings['paths'], $settings['options']);

                return $twig;
        },
]);

// Build PHP-DI Container instance
$container = $containerBuilder->build();

$container->set('db', function (ContainerInterface $container) {
        $settings = $container->get('settings');
        $dsn = $settings['dsn'];
        return new Db($dsn);
});

$container->set('validator', function (ContainerInterface $container) {
        return new Awurth\SlimValidation\Validator();
});

// Instantiate the app
AppFactory::setContainer($container);
$app = AppFactory::create();
$callableResolver = $app->getCallableResolver();

// Register middleware
$middleware = require __DIR__ . '/../app/middleware.php';
$middleware($app);

// Register routes
$routes = require __DIR__ . '/../app/routes.php';
$routes($app);

/** @var bool $displayErrorDetails */
$displayErrorDetails = $container->get('settings')['displayErrorDetails'];

// Create Request object from globals
$serverRequestCreator = ServerRequestCreatorFactory::create();
$request = $serverRequestCreator->createServerRequestFromGlobals();

// Create Error Handler
$responseFactory = $app->getResponseFactory();
$errorHandler = new HttpErrorHandler($callableResolver, $responseFactory);

// Create Shutdown Handler
$shutdownHandler = new ShutdownHandler($request, $errorHandler, $displayErrorDetails);
register_shutdown_function($shutdownHandler);

// Parse json, form data and xml
$app->addBodyParsingMiddleware();

// Add Routing Middleware
$app->addRoutingMiddleware();

// Add Error Middleware
$errorMiddleware = $app->addErrorMiddleware($displayErrorDetails, false, false);
$errorMiddleware->setDefaultErrorHandler($errorHandler);

// Run App & Emit Response
$response = $app->handle($request);
$responseEmitter = new ResponseEmitter();
$responseEmitter->emit($response);
