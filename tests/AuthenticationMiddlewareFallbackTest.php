<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Extractor\ChainedPayloadExtractor;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthenticationMiddlewareFallbackTest extends TestCase
{
    #[DataProvider('candidateWork')]
    public function testNestedFallbackPreservesAcceptedOuterCredentials(bool $tentativeWork): void
    {
        $observed = new FallbackObservation();
        $identity = $this->identity();

        $response = $this->processNested($observed, $identity,
            function (int $candidate, CredentialTransportState $state) use ($observed, $identity, $tentativeWork): AuthenticationResult {
                if ($candidate === 0) {
                    if ($tentativeWork) $this->tentative($state, $observed, 'failed');

                    return new AuthenticationResult(new InvalidCredentials(), continueOnFailure: true);
                }

                return $this->accepted($identity);
            },
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('outer', $response->getHeaderLine('X-Outer-Credential'));
        self::assertSame('', $response->getHeaderLine('X-Failed-Credential'));
        self::assertSame($tentativeWork ? ['failed'] : [], $observed->discarded);
        self::assertTrue($observed->session->active);
        self::assertSame($identity, $observed->request?->getAttribute(IdentityInterface::class));
        self::assertSame($observed->session, $observed->request?->getAttribute(AuthenticationStateInterface::class));
        self::assertSame($observed->session, $observed->request?->getAttribute(FallbackSession::class));
        self::assertSame($observed->transport, $observed->request?->getAttribute(CredentialTransportState::class));
    }

    /** @return iterable<string, array{bool}> */
    public static function candidateWork(): iterable
    {
        yield 'no tentative candidate work' => [false];
        yield 'tentative candidate credential' => [true];
    }

    #[DataProvider('terminalOutcomes')]
    public function testTerminalOutcomeStillCancelsAllPendingCredentials(string $outcome): void
    {
        $observed = new FallbackObservation();
        $response = $this->processNested($observed, $this->identity(),
            function (int $candidate, CredentialTransportState $state) use ($observed, $outcome): AuthenticationResult {
                $this->tentative($state, $observed, $candidate === 0 ? 'failed' : 'last');
                if ($candidate === 0) return new AuthenticationResult(new InvalidCredentials(), continueOnFailure: true);

                return $outcome === 'mismatched identity'
                    ? $this->accepted($this->identity('018f6d5d-3f7a-7a9b-8c2f-123456789abd'))
                    : new AuthenticationResult(new InvalidCredentials(), continueOnFailure: $outcome === 'exhausted fallback');
            },
        );

        self::assertEqualsCanonicalizing(['failed', 'last', 'outer'], $observed->discarded);
        self::assertFalse($observed->session->active);
        self::assertNull($observed->request?->getAttribute(IdentityInterface::class));
        self::assertNull($observed->request?->getAttribute(AuthenticationStateInterface::class));
        self::assertNull($observed->request?->getAttribute(FallbackSession::class));
        self::assertInstanceOf(InvalidCredentials::class, $observed->request?->getAttribute(DeniedReasonInterface::class));
        self::assertSame('', $response->getHeaderLine('X-Outer-Credential'));
        self::assertSame('', $response->getHeaderLine('X-Failed-Credential'));
        self::assertSame('', $response->getHeaderLine('X-Last-Credential'));
    }

    /** @return iterable<string, array{string}> */
    public static function terminalOutcomes(): iterable
    {
        foreach (['hard denial', 'exhausted fallback', 'mismatched identity'] as $outcome) yield $outcome => [$outcome];
    }

    public function testOwnerCompensatesAllRemainingWorkWhenLaterCandidateThrows(): void
    {
        $observed = new FallbackObservation();
        $failure = new \RuntimeException('Second attempt failed.');

        try {
            $this->processNested($observed, $this->identity(),
                function (int $candidate, CredentialTransportState $state) use ($observed, $failure): AuthenticationResult {
                    $this->tentative($state, $observed, $candidate === 0 ? 'failed' : 'last');
                    if ($candidate === 0) return new AuthenticationResult(new InvalidCredentials(), continueOnFailure: true);

                    throw $failure;
                },
            );
            self::fail('Attempt failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertNull($observed->request);
        self::assertEqualsCanonicalizing(['failed', 'last', 'outer'], $observed->discarded);
        self::assertFalse($observed->session->active);
        $observed->transport?->discardQueued();
        self::assertEqualsCanonicalizing(['failed', 'last', 'outer'], $observed->discarded);
    }

    #[DataProvider('globalCancellations')]
    public function testExplicitGlobalCancellationInsideCandidateIsNotUndone(bool $terminalClear): void
    {
        $observed = new FallbackObservation();
        $identity = $this->identity();
        $replacement = new FallbackSession();

        $response = $this->processNested($observed, $identity,
            function (int $candidate, CredentialTransportState $state) use ($observed, $identity, $replacement, $terminalClear): AuthenticationResult {
                if ($candidate === 0) {
                    if ($terminalClear) $state->clear(new FallbackStorage('X-Outer-Credential'));
                    else $state->discardQueued();
                    $this->tentative($state, $observed, 'failed');

                    return new AuthenticationResult(new InvalidCredentials(), continueOnFailure: true);
                }
                $state->onDiscard(static function () use ($observed, $replacement): void {
                    $observed->discarded[] = 'replacement';
                    $replacement->active = false;
                });

                return new AuthenticationResult($identity,
                    transportPayload: new FallbackCredential('replacement'),
                    state: $replacement,
                    evidence: new AuthenticationEvidence(['test']),
                );
            },
        );

        self::assertSame($terminalClear ? ['outer', 'failed', 'replacement'] : ['outer', 'failed'], $observed->discarded);
        self::assertFalse($observed->session->active);
        self::assertSame(!$terminalClear, $replacement->active);
        self::assertSame($replacement, $observed->request?->getAttribute(AuthenticationStateInterface::class));
        self::assertSame('', $response->getHeaderLine('X-Outer-Credential'));
        self::assertSame('', $response->getHeaderLine('X-Failed-Credential'));
        self::assertSame($terminalClear ? '' : 'replacement', $response->getHeaderLine('X-Inner-Credential'));
        self::assertSame($terminalClear, $observed->transport?->cleared);
    }

    /** @return iterable<string, array{bool}> */
    public static function globalCancellations(): iterable
    {
        yield 'replacement' => [false];
        yield 'terminal clear' => [true];
    }

    /** @param \Closure(int, CredentialTransportState): AuthenticationResult $attempt */
    private function processNested(FallbackObservation $observed, IdentityInterface $identity, \Closure $attempt): ResponseInterface
    {
        $outerAuth = $this->createStub(AuthenticatorInterface::class);
        $outerAuth->method('attempt')->willReturnCallback(
            static function (object $payload, ContextInterface $context) use ($observed, $identity): AuthenticationResult {
                $state = $context->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $observed->transport = $state;
                $state->onDiscard(static function () use ($observed): void {
                    $observed->session->active = false;
                    $observed->discarded[] = 'outer';
                });

                return new AuthenticationResult($identity,
                    transportPayload: new FallbackCredential('outer'),
                    state: $observed->session,
                    evidence: new AuthenticationEvidence(['test']),
                );
            },
        );
        $outer = new AuthenticationMiddleware($this->extractor(0), $outerAuth, new FallbackStorage('X-Outer-Credential'));
        $innerAuth = $this->createStub(AuthenticatorInterface::class);
        $innerAuth->method('attempt')->willReturnCallback(
            static function (object $payload, ContextInterface $context) use ($observed, $attempt): AuthenticationResult {
                self::assertInstanceOf(FallbackCandidate::class, $payload);
                $state = $context->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                self::assertSame($observed->transport, $state);

                return $attempt($payload->index, $state);
            },
        );
        $inner = new AuthenticationMiddleware(
            new ChainedPayloadExtractor($this->extractor(0), $this->extractor(1)),
            $innerAuth,
            new FallbackStorage('X-Inner-Credential'),
        );
        $endpoint = $this->createStub(RequestHandlerInterface::class);
        $endpoint->method('handle')->willReturnCallback(
            static function (ServerRequestInterface $request) use ($observed): ResponseInterface {
                $observed->request = $request;

                return new Response(204);
            },
        );
        $nested = $this->createStub(RequestHandlerInterface::class);
        $nested->method('handle')->willReturnCallback(
            static fn(ServerRequestInterface $request): ResponseInterface => $inner->process($request, $endpoint),
        );

        return $outer->process(new ServerRequest('GET', '/'), $nested);
    }

    private function tentative(CredentialTransportState $state, FallbackObservation $observed, string $name): void
    {
        $state->queue(new FallbackStorage('X-' . ucfirst($name) . '-Credential'), new FallbackCredential($name));
        $state->onDiscard(static function () use ($observed, $name): void { $observed->discarded[] = $name; });
    }

    private function accepted(IdentityInterface $identity): AuthenticationResult
    {
        return new AuthenticationResult($identity, evidence: new AuthenticationEvidence(['test']));
    }

    private function extractor(int $index): PayloadExtractorInterface
    {
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new FallbackCandidate($index));

        return $extractor;
    }

    private function identity(string $uuid = '018f6d5d-3f7a-7a9b-8c2f-123456789abc'): IdentityInterface
    {
        return new readonly class(Uuid::fromString($uuid)) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
    }
}

final class FallbackObservation
{
    public FallbackSession $session;
    public ?CredentialTransportState $transport = null;
    public ?ServerRequestInterface $request = null;
    /** @var list<string> */
    public array $discarded = [];
    public function __construct() { $this->session = new FallbackSession(); }
}

final class FallbackSession implements AuthenticationStateInterface
{
    public bool $active = true;
}

final readonly class FallbackCandidate
{
    public function __construct(public int $index) {}
}

final readonly class FallbackCredential
{
    public function __construct(public string $value) {}
}

final readonly class FallbackStorage implements PayloadStorageInterface
{
    public function __construct(private string $header) {}
    public function store(ServerRequestInterface $request, ResponseInterface $response, object $payload): ResponseInterface
    {
        if (!$payload instanceof FallbackCredential) throw new \InvalidArgumentException('Unsupported credential.');

        return $response->withHeader($this->header, $payload->value);
    }
    public function remove(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        return $response->withoutHeader($this->header);
    }
}
