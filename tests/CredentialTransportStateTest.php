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
    public function testClearDuringStorageCancelsThePublishingBatch(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $storage = new HeaderStorageFixture();
        $clearingStorage = $this->createStub(PayloadStorageInterface::class);
        $clearingStorage->method('store')->willReturnCallback(
            static function (ServerRequestInterface $request, ResponseInterface $response, object $payload) use ($state, $storage): ResponseInterface {
                $state->clear($storage);

                return $storage->store($request, $response, $payload);
            },
        );
        $clearingStorage->method('remove')->willReturnCallback($storage->remove(...));
        $laterStorage = $this->createMock(PayloadStorageInterface::class);
        $laterStorage->expects(self::never())->method('store');
        $laterStorage->method('remove')->willReturnCallback(
            static fn(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface => $response,
        );
        $state->queue($clearingStorage, new HeaderPayloadFixture('cancelled'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'first'; });
        $state->queue($laterStorage, new HeaderPayloadFixture('also-cancelled'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'second'; });
        $request = (new ServerRequest('GET', '/'))->withAttribute(CredentialTransportState::class, $state);

        $response = $state->apply($request, new Response());

        self::assertSame(['second', 'first'], $discarded);
        self::assertSame('', $response->getHeaderLine('X-Credential'));
        self::assertTrue($state->cleared);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $state->discardQueued();
        self::assertSame(['second', 'first'], $discarded);
    }

    public function testClearDuringCacheHeaderPublicationCancelsTheCredential(): void
    {
        $state = new CredentialTransportState();
        $storage = new HeaderStorageFixture();
        $discarded = 0;
        $state->queue($storage, new HeaderPayloadFixture('cancelled'));
        $state->onDiscard(static function () use (&$discarded): void { ++$discarded; });
        $response = new class($state, $storage) extends Response {
            public function __construct(
                private readonly CredentialTransportState $state,
                private readonly PayloadStorageInterface $storage,
            ) {
                parent::__construct();
            }

            public function withHeader($name, $value): ResponseInterface
            {
                if ($name === 'Cache-Control') $this->state->clear($this->storage);

                return parent::withHeader($name, $value);
            }
        };
        $request = (new ServerRequest('GET', '/'))->withAttribute(CredentialTransportState::class, $state);

        $response = $state->apply($request, $response);

        self::assertSame(1, $discarded);
        self::assertSame('', $response->getHeaderLine('X-Credential'));
        self::assertTrue($state->cleared);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $state->discardQueued();
        self::assertSame(1, $discarded);
    }

    public function testReentrantClearDuringCompensationAndRemovalDoesNotRepeatCallbacks(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willReturnCallback(
            static function (ServerRequestInterface $request, ResponseInterface $response) use ($state, $storage): ResponseInterface {
                $state->clear($storage);

                return $response->withHeader('X-Credential', 'cancelled');
            },
        );
        $storage->method('remove')->willReturnCallback(
            static function (ServerRequestInterface $request, ResponseInterface $response) use ($state, $storage): ResponseInterface {
                $state->clear($storage);

                return $response->withoutHeader('X-Credential');
            },
        );
        $state->queue($storage, new HeaderPayloadFixture('cancelled'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'first'; });
        $state->onDiscard(static function () use ($state, $storage, &$discarded): void {
            $discarded[] = 'second';
            $state->clear($storage);
        });

        $response = $state->apply(new ServerRequest('GET', '/'), new Response());

        self::assertSame(['second', 'first'], $discarded);
        self::assertSame('', $response->getHeaderLine('X-Credential'));
        $state->discardQueued();
        self::assertSame(['second', 'first'], $discarded);
    }

    public function testCleanupFailureTakesPrecedenceAndEveryCallbackStillRunsOnce(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $failure = new \RuntimeException('Revocation failed.');
        $state->queue(new HeaderStorageFixture(new TransportException('Publication failed.')), new HeaderPayloadFixture('cancelled'));
        $state->onDiscard(static function () use (&$discarded): void {
            $discarded[] = 'first';
            throw new \RuntimeException('Older credential revocation failed.');
        });
        $state->onDiscard(static function () use ($failure, &$discarded): void {
            $discarded[] = 'second';
            throw $failure;
        });

        try {
            $state->apply(new ServerRequest('GET', '/'), new Response());
            self::fail('Failed cleanup must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
        $state->discardQueued();

        self::assertSame(['second', 'first'], $discarded);
        self::assertTrue($state->empty);
    }

    public function testRemovalFailureAfterClearDoesNotRepeatBatchCompensation(): void
    {
        $state = new CredentialTransportState();
        $discarded = 0;
        $failure = new TransportException('Removal failed.');
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willReturnCallback(
            static function (ServerRequestInterface $request, ResponseInterface $response) use ($state, $storage): ResponseInterface {
                $state->clear($storage);

                return $response;
            },
        );
        $storage->method('remove')->willThrowException($failure);
        $state->queue($storage, new HeaderPayloadFixture('cancelled'));
        $state->onDiscard(static function () use (&$discarded): void { ++$discarded; });

        try {
            $state->apply(new ServerRequest('GET', '/'), new Response());
            self::fail('Removal failure must propagate.');
        } catch (TransportException $exception) {
            self::assertSame($failure, $exception);
        }
        self::assertSame(1, $discarded);
        $state->discardQueued();

        self::assertSame(1, $discarded);
    }

    public function testClearingOneRequestDoesNotDiscardAnotherRequestsCredential(): void
    {
        $storage = new HeaderStorageFixture();
        $first = new CredentialTransportState();
        $second = new CredentialTransportState();
        $discarded = [];
        $first->queue($storage, new HeaderPayloadFixture('first'));
        $first->onDiscard(static function () use (&$discarded): void { $discarded[] = 'first'; });
        $second->queue($storage, new HeaderPayloadFixture('second'));
        $second->onDiscard(static function () use (&$discarded): void { $discarded[] = 'second'; });

        $first->clear($storage);
        $firstResponse = $first->apply(new ServerRequest('GET', '/first'), new Response());
        $secondResponse = $second->apply(new ServerRequest('GET', '/second'), new Response());

        self::assertSame(['first'], $discarded);
        self::assertSame('', $firstResponse->getHeaderLine('X-Credential'));
        self::assertSame('second', $secondResponse->getHeaderLine('X-Credential'));
    }

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
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
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

    public function testCacheHeaderFailureCompensatesTheStoredCredentialExactlyOnce(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $writtenHeaders = [];
        $failure = new \RuntimeException('Cache header failed.');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, mixed $value) use ($response, $failure, &$writtenHeaders): ResponseInterface {
                if ($name === 'Cache-Control') throw $failure;
                $writtenHeaders[$name] = $value;

                return $response;
            },
        );
        $state->queue(new HeaderStorageFixture(), new HeaderPayloadFixture('successor'));
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'first'; });
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'second'; });

        try {
            $state->apply(new ServerRequest('GET', '/'), $response);
            self::fail('Cache header failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
        $state->discardQueued();

        self::assertSame(['X-Credential' => 'successor'], $writtenHeaders);
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
