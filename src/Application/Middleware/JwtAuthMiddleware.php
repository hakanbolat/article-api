<?php
declare(strict_types=1);

namespace App\Application\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Container\ContainerInterface;
use \Firebase\JWT\JWT;

class JwtAuthMiddleware implements Middleware
{
    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;
    
    /**
     * @var ContainerInterface
     */
    private $container;

    /**
     * @param ResponseFactoryInterface $responseFactory
     */
    public function __construct(ResponseFactoryInterface $responseFactory, ContainerInterface $container)
    {
        $this->responseFactory = $responseFactory;
        $this->container = $container;
    }

    /**
     * {@inheritdoc}
     */
    public function process(Request $request, RequestHandler $handler): Response
    {
        $authorization = explode(' ', (string)$request->getHeaderLine('Authorization'));
        $type = $authorization[0] ?? '';
        $credentials = $authorization[1] ?? '';
        $payload = $this->validateToken($credentials);
        if ($type === 'Bearer' && $payload) {
            $request = $request->withAttribute('userid', $payload->iss);
            return $handler->handle($request);
        }

        return $this->responseFactory->createResponse()
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(401, 'Unauthorized');
    }

    /**
     * @param string $token
     * @return object,boolean
     */
    protected function validateToken($token)
    {
        try {
            $secretkey = $this->container->get('settings')['secret_key'];
            $result = JWT::decode($token, $secretkey, array('HS256'));
            return $result;
        } catch (\Exception $e) {
            return false;
        }
        
    }
}
