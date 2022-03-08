<?php

namespace App\Action;

use App\Responder\Responder;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Yaml\Yaml;

final class SwaggerUiAction
{
    /**
     * @var Responder
     */
    private $responder;

    /**
     * The constructor.
     *
     * @param Responder $responder The responder
     */
    public function __construct(Responder $responder)
    {
        $this->responder = $responder;
    }

    /**
     * Action.
     *
     * @param ServerRequestInterface $request The request
     * @param ResponseInterface $response The response
     *
     * @return ResponseInterface The response
     */
    public function __invoke(
        ServerRequestInterface $request, 
        ResponseInterface $response
    ): ResponseInterface {
        $openapi = \OpenApi\scan('../app/');
        $yamlFile = $openapi->toYaml();

        $viewData = [
            'spec' =>json_encode(Yaml::parse($yamlFile)),
        ];

        return $this->responder->render('docs/swagger.twig', $viewData);
    }
}
