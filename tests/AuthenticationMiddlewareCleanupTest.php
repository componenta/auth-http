<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthenticationMiddlewareCleanupTest extends TestCase
{
    public function testOwnerCompensatesWhenRequestDecorationFailsAfterAuthentication(): void
    {
        $observed = new MiddlewareCleanupObservation();
        $middleware = $this->middleware(
            fn(object $payload, ContextInterface $context): AuthenticationResult =>
                $this->issuedResult($context, $observed),
        );
        $failure = new \RuntimeException('Request decoration failed.');
        $request = new FailingDecorationRequest(static fn(): bool => true, $failure);

        try {
            $middleware->process($request, $this->unreachedHandler());
            self::fail('Request decoration failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(1, $observed->discarded);
        self::assertInstanceOf(CredentialTransportState::class, $observed->state);
        self::assertTrue($observed->state->empty);
        $observed->state->discardQueued();
        self::assertSame(1, $observed->discarded);
    }

    public function testBorrowerLeavesFailureCompensationToTheExistingOwner(): void
    {
        $observed = new MiddlewareCleanupObservation();
        $state = new CredentialTransportState();
        $middleware = $this->middleware(
            fn(object $payload, ContextInterface $context): AuthenticationResult =>
                $this->issuedResult($context, $observed),
        );
        $failure = new \RuntimeException('Request decoration failed.');
        $request = (new FailingDecorationRequest(static fn(): bool => true, $failure))
            ->withAttribute(CredentialTransportState::class, $state);

        try {
            $middleware->process($request, $this->unreachedHandler());
            self::fail('Request decoration failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($state, $observed->state);
        self::assertSame(0, $observed->discarded);
        self::assertFalse($state->empty);
        $state->discardQueued();
        self::assertSame(1, $observed->discarded);
    }

    public function testOuterOwnerCompensatesNestedFailureExactlyOnce(): void
    {
        $outerObserved = new MiddlewareCleanupObservation();
        $innerObserved = new MiddlewareCleanupObservation();
        $failDecoration = false;
        $outer = $this->middleware(
            fn(object $payload, ContextInterface $context): AuthenticationResult =>
                $this->issuedResult($context, $outerObserved),
        );
        $inner = $this->middleware(
            function (object $payload, ContextInterface $context) use ($innerObserved, &$failDecoration): AuthenticationResult {
                $failDecoration = true;

                return $this->issuedResult($context, $innerObserved);
            },
        );
        $failure = new \RuntimeException('Nested request decoration failed.');
        $request = new FailingDecorationRequest(
            static function () use (&$failDecoration): bool { return $failDecoration; },
            $failure,
        );
        $downstream = $this->unreachedHandler();
        $nested = $this->createStub(RequestHandlerInterface::class);
        $nested->method('handle')->willReturnCallback(
            static fn(ServerRequestInterface $request) => $inner->process($request, $downstream),
        );

        try {
            $outer->process($request, $nested);
            self::fail('Nested request decoration failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(1, $outerObserved->discarded);
        self::assertSame(1, $innerObserved->discarded);
        self::assertInstanceOf(CredentialTransportState::class, $outerObserved->state);
        self::assertSame($outerObserved->state, $innerObserved->state);
        self::assertTrue($outerObserved->state->empty);
        $outerObserved->state->discardQueued();
        self::assertSame(1, $outerObserved->discarded);
        self::assertSame(1, $innerObserved->discarded);
    }

    /** @param \Closure(object, ContextInterface): AuthenticationResult $attempt */
    private function middleware(\Closure $attempt): AuthenticationMiddleware
    {
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturnCallback($attempt);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');

        return new AuthenticationMiddleware($extractor, $authenticator, $storage);
    }

    private function issuedResult(
        ContextInterface $context,
        MiddlewareCleanupObservation $observed,
    ): AuthenticationResult {
        $state = $context->getAttribute(CredentialTransportState::class);
        self::assertInstanceOf(CredentialTransportState::class, $state);
        $observed->state = $state;
        $state->onDiscard(static function () use ($observed): void { ++$observed->discarded; });
        $identity = new readonly class(Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        )) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };

        return new AuthenticationResult(
            $identity,
            transportPayload: new \stdClass(),
            evidence: new AuthenticationEvidence(['test']),
        );
    }

    private function unreachedHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        return $handler;
    }
}

final class MiddlewareCleanupObservation
{
    public int $discarded = 0;
    public ?CredentialTransportState $state = null;
}

final class FailingDecorationRequest extends ServerRequest
{
    /** @param \Closure(): bool $shouldFail */
    public function __construct(
        private readonly \Closure $shouldFail,
        private readonly \RuntimeException $failure,
    ) {
        parent::__construct('GET', '/');
    }

    public function withoutAttribute($name): ServerRequestInterface
    {
        if (($this->shouldFail)()) {
            throw $this->failure;
        }

        return parent::withoutAttribute($name);
    }
}
