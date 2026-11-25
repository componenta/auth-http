<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
final readonly class ReplacingPayloadStorage implements PayloadStorageInterface
{
    public function __construct(private PayloadStorageInterface $storage) {}
    public function store(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
        #[\SensitiveParameter] object $payload,
    ): ResponseInterface
    {
        $state = $request->getAttribute(CredentialTransportState::class);
        if ($state instanceof CredentialTransportState) $state->discardQueued();
        return $this->storage->store($request, $this->storage->remove($request, $response), $payload);
    }
    public function remove(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
    ): ResponseInterface
    {
        return $this->storage->remove($request, $response);
    }
}
