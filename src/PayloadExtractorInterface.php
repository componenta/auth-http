<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Psr\Http\Message\ServerRequestInterface;
interface PayloadExtractorInterface
{
    /** @throws InvalidPayloadException */
    public function extract(#[\SensitiveParameter] ServerRequestInterface $request): ?object;
}
