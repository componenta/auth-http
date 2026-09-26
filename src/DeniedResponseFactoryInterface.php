<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Componenta\Auth\DeniedReasonInterface;
use Psr\Http\Message\ResponseInterface;
interface DeniedResponseFactoryInterface
{
    public function create(#[\SensitiveParameter] DeniedReasonInterface $reason): ResponseInterface;
}
