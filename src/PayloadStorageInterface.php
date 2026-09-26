<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Componenta\Auth\Http\Exception\TransportException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
interface PayloadStorageInterface
{
    /** @throws TransportException */
    public function store(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
        #[\SensitiveParameter] object $payload,
    ): ResponseInterface;
    /** @throws TransportException */
    public function remove(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
    ): ResponseInterface;
}
