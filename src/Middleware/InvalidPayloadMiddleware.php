<?php
declare(strict_types=1);
namespace Componenta\Auth\Http\Middleware;
use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\JsonResponseBody;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
final readonly class InvalidPayloadMiddleware implements MiddlewareInterface
{
    public function __construct(private ResponseFactoryInterface $responseFactory) {}
    public function process(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] RequestHandlerInterface $handler,
    ): ResponseInterface
    {
        try { return $handler->handle($request); }
        catch (InvalidPayloadException $e) {
            $response=$this->responseFactory->createResponse(400);
            JsonResponseBody::write($response, ['error'=>'invalid_payload','field'=>$e->field]);
            return $response->withHeader('Content-Type','application/json')->withHeader('Cache-Control','no-store')->withHeader('Pragma','no-cache');
        }
    }
}
