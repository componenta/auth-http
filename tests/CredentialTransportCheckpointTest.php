<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CredentialTransportCheckpointTest extends TestCase
{
    public function testRollbackCancelsOnlyNewPendingWorkOnceInReverseOrder(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $this->register($state, $discarded, 'outer');
        $rollback = $state->checkpoint();
        $this->register($state, $discarded, 'first');
        $this->register($state, $discarded, 'second');

        $rollback();
        $this->register($state, $discarded, 'later');
        $rollback();
        $response = $state->apply(new ServerRequest('GET', '/'), new Response());

        self::assertSame(['second', 'first'], $discarded);
        self::assertSame(['outer', 'later'], $response->getHeader('X-Credential'));
    }

    public function testNestedCheckpointsDoNotRestoreAlreadyCancelledWork(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $this->register($state, $discarded, 'outer');
        $rollbackOuterCandidate = $state->checkpoint();
        $this->register($state, $discarded, 'middle');
        $rollbackInnerCandidate = $state->checkpoint();
        $this->register($state, $discarded, 'inner');

        $rollbackInnerCandidate();
        $this->register($state, $discarded, 'later');
        $rollbackOuterCandidate();
        $response = $state->apply(new ServerRequest('GET', '/'), new Response());

        self::assertSame(['inner', 'later', 'middle'], $discarded);
        self::assertSame(['outer'], $response->getHeader('X-Credential'));
    }

    public function testThrowingRollbackIsConsumedBeforeReentrantCallbacksAndPreservesTheirNewWork(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $this->register($state, $discarded, 'outer');
        $rollback = $state->checkpoint();
        $state->queue($this->storage('failed'), new \stdClass());
        $firstFailure = new \RuntimeException('Most recent compensation failed.');
        $state->onDiscard(static function () use (&$discarded): void {
            $discarded[] = 'earlier';
            throw new \RuntimeException('Earlier compensation also failed.');
        });
        $state->onDiscard(function () use ($state, $rollback, &$discarded, $firstFailure): void {
            $discarded[] = 'latest';
            $this->register($state, $discarded, 'new');
            $rollback();
            throw $firstFailure;
        });

        try {
            $rollback();
            self::fail('Compensation failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($firstFailure, $exception);
        }
        $rollback();
        $response = $state->apply(new ServerRequest('GET', '/'), new Response());

        self::assertSame(['latest', 'earlier'], $discarded);
        self::assertSame(['outer', 'new'], $response->getHeader('X-Credential'));
    }

    #[DataProvider('globalCancellations')]
    public function testGlobalCancellationFromRollbackCallbackRemainsGlobal(bool $terminalClear): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $storage = $this->storage('unused');
        $this->register($state, $discarded, 'outer');
        $rollback = $state->checkpoint();
        $this->register($state, $discarded, 'first');
        $state->onDiscard(static function () use ($state, $storage, $terminalClear, &$discarded): void {
            $discarded[] = 'last';
            if ($terminalClear) $state->clear($storage);
            else $state->discardQueued();
        });

        $rollback();
        $response = $state->apply(new ServerRequest('GET', '/'), new Response());
        $rollback();
        $state->discardQueued();

        self::assertSame(['last', 'outer', 'first'], $discarded);
        self::assertSame([], $response->getHeader('X-Credential'));
        self::assertSame($terminalClear, $state->cleared);
    }

    public function testRollbackIncludesNewWorkRegisteredAfterAnExplicitGlobalDiscard(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $this->register($state, $discarded, 'outer');
        $rollback = $state->checkpoint();
        $state->discardQueued();
        $this->register($state, $discarded, 'candidate');

        $rollback();
        $response = $state->apply(new ServerRequest('GET', '/'), new Response());

        self::assertSame(['outer', 'candidate'], $discarded);
        self::assertSame([], $response->getHeader('X-Credential'));
    }

    public function testRollbackInsidePublicationLeavesTheActiveBatchToItsOwner(): void
    {
        $state = new CredentialTransportState();
        $discarded = [];
        $this->register($state, $discarded, 'outer');
        $rollback = $state->checkpoint();
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willReturnCallback(
            function (ServerRequestInterface $request, ResponseInterface $response) use ($state, $rollback, &$discarded): ResponseInterface {
                $this->register($state, $discarded, 'pending');
                $rollback();

                return $response->withAddedHeader('X-Credential', 'active');
            },
        );
        $state->queue($storage, new \stdClass());
        $state->onDiscard(static function () use (&$discarded): void { $discarded[] = 'active'; });

        $response = $state->apply(new ServerRequest('GET', '/'), new Response());
        $state->discardQueued();

        self::assertSame(['pending'], $discarded);
        self::assertSame(['outer', 'active'], $response->getHeader('X-Credential'));
    }

    /** @return iterable<string, array{bool}> */
    public static function globalCancellations(): iterable
    {
        yield 'discard' => [false];
        yield 'clear' => [true];
    }

    /** @param list<string> $discarded */
    private function register(CredentialTransportState $state, array &$discarded, string $name): void
    {
        $state->queue($this->storage($name), new \stdClass());
        $state->onDiscard(static function () use (&$discarded, $name): void { $discarded[] = $name; });
    }

    private function storage(string $value): PayloadStorageInterface
    {
        return new readonly class($value) implements PayloadStorageInterface {
            public function __construct(private string $value) {}
            public function store(ServerRequestInterface $request, ResponseInterface $response, object $payload): ResponseInterface
            {
                return $response->withAddedHeader('X-Credential', $this->value);
            }
            public function remove(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
            {
                return $response->withoutHeader('X-Credential');
            }
        };
    }
}
