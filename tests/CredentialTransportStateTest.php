<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Exception\TransportException;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CredentialTransportStateTest extends TestCase
{
    public function testQueuedReplacementCommitsWithoutDiscardingItsOwnCredential(): void
    {
        $state = new CredentialTransportState();
        $discarded = false;
        $state->queue(new ReplacingPayloadStorage(new HeaderStorageFixture()), new HeaderPayloadFixture('successor'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded = true; });
        $request = (new ServerRequest('GET', '/'))->withAttribute(CredentialTransportState::class, $state);

        $response = $state->apply($request, new Response(200, ['X-Credential' => 'previous']));

        self::assertFalse($discarded, 'Publishing a queued credential must not compensate it as discarded.');
        self::assertSame('successor', $response->getHeaderLine('X-Credential'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertTrue($state->empty);
    }

    public function testDirectReplacementStillDiscardsEarlierQueuedCredential(): void
    {
        $state = new CredentialTransportState();
        $discarded = 0;
        $storage = new HeaderStorageFixture();
        $state->queue($storage, new HeaderPayloadFixture('queued'));
        $state->onDiscard(static function () use (&$discarded): void { ++$discarded; });
        $request = (new ServerRequest('GET', '/'))->withAttribute(CredentialTransportState::class, $state);

        $response = (new ReplacingPayloadStorage($storage))->store(
            $request,
            new Response(),
            new HeaderPayloadFixture('replacement'),
        );
        $response = $state->apply($request, $response);

        self::assertSame(1, $discarded);
        self::assertSame('replacement', $response->getHeaderLine('X-Credential'));
        self::assertTrue($state->empty);
    }

    public function testFailedQueuedReplacementCompensatesEachCredentialOnceInReverseOrder(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $failure = new TransportException('Storage failed.');
        $state->queue(new ReplacingPayloadStorage(new HeaderStorageFixture($failure)), new HeaderPayloadFixture('successor'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'first'; });
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'second'; });
        $request = (new ServerRequest('GET', '/'))->withAttribute(CredentialTransportState::class, $state);

        try {
            $state->apply($request, new Response());
            self::fail('Storage failure must propagate.');
        } catch (TransportException $exception) {
            self::assertSame($failure, $exception);
        }
        $state->discardQueued();

        self::assertSame(['second', 'first'], $discarded);
        self::assertTrue($state->empty);
    }
}

final readonly class HeaderPayloadFixture
{
    public function __construct(public string $value) {}
}

final readonly class HeaderStorageFixture implements PayloadStorageInterface
{
    public function __construct(private ?TransportException $failure = null) {}

    public function store(ServerRequestInterface $request, ResponseInterface $response, object $payload): ResponseInterface
    {
        if ($this->failure !== null) throw $this->failure;
        if (!$payload instanceof HeaderPayloadFixture) throw new \InvalidArgumentException('Unexpected payload.');

        return $response->withHeader('X-Credential', $payload->value);
    }

    public function remove(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        return $response->withoutHeader('X-Credential');
    }
}
