<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CredentialTransportStateRedactionTest extends TestCase
{
    public function testDebugOutputDoesNotExposeQueuedCredentialsOrCapturedSecrets(): void
    {
        $state = new CredentialTransportState();
        $storageSecret = 'synthetic-storage-secret';
        $payloadSecret = 'synthetic-payload-secret';
        $compensationSecret = 'synthetic-compensation-secret';
        $storage = new readonly class($storageSecret) implements PayloadStorageInterface {
            public function __construct(private string $secret) {}
            public function store(ServerRequestInterface $request, ResponseInterface $response, object $payload): ResponseInterface
            {
                return $response;
            }
            public function remove(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
            {
                return $response;
            }
        };
        $state->queue($storage, (object) ['credential' => $payloadSecret]);
        $discarded = [];
        $state->onDiscard(static function () use ($compensationSecret, &$discarded): void {
            $discarded[] = $compensationSecret;
        });

        ob_start();
        try {
            var_dump($state);
            $dump = ob_get_contents();
        } finally {
            ob_end_clean();
        }

        self::assertIsString($dump);
        self::assertStringNotContainsString($storageSecret, $dump);
        self::assertStringNotContainsString($payloadSecret, $dump);
        self::assertStringNotContainsString($compensationSecret, $dump);
        self::assertStringContainsString('[REDACTED]', $dump);

        $state->discardQueued();
        self::assertSame([$compensationSecret], $discarded);
    }
}
