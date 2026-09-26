<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Psr\Http\Message\ResponseInterface;
final class CredentialResponseHeaders
{
    private function __construct() {}
    public static function apply(#[\SensitiveParameter] ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('Cache-Control', 'no-store')->withHeader('Pragma', 'no-cache');
    }
}
