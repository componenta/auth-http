<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\Authenticator;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Extractor\ChainedPayloadExtractor;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ChainedAuthenticationTest extends TestCase
{
    public function testSoftFailureOfFirstCredentialFallsBackToSecondCredential(): void
    {
        $identity = new ChainedIdentityFixture();
        $extractor = new ChainedPayloadExtractor(
            new FixedPayloadExtractorFixture(new FirstPayloadFixture()),
            new FixedPayloadExtractorFixture(new SecondPayloadFixture()),
        );
        $authenticator = new Authenticator(
            new FirstStrategyFixture(),
            new SecondStrategyFixture($identity),
        );
        $handler = new CapturingHandlerFixture();

        $response = (new AuthenticationMiddleware(
            $extractor,
            $authenticator,
        ))->process(
            new ServerRequest('GET', '/'),
            $handler,
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame($identity, $handler->identity);
    }
}

final class FirstPayloadFixture {}
final class SecondPayloadFixture {}

final readonly class FixedPayloadExtractorFixture implements
    PayloadExtractorInterface
{
    public function __construct(private object $payload) {}

    public function extract(ServerRequestInterface $request): ?object
    {
        return $this->payload;
    }
}

final readonly class FirstStrategyFixture implements
    AuthenticationStrategyInterface
{
    public function supports(
        object $payload,
        ContextInterface $context,
    ): bool {
        return $payload instanceof FirstPayloadFixture;
    }

    public function attempt(
        object $payload,
        ContextInterface $context,
    ): AuthenticationResult {
        return new AuthenticationResult(
            new InvalidCredentials(),
            continueOnFailure: true,
        );
    }
}

final readonly class SecondStrategyFixture implements
    AuthenticationStrategyInterface
{
    public function __construct(private IdentityInterface $identity) {}

    public function supports(
        object $payload,
        ContextInterface $context,
    ): bool {
        return $payload instanceof SecondPayloadFixture;
    }

    public function attempt(
        object $payload,
        ContextInterface $context,
    ): AuthenticationResult {
        return new AuthenticationResult(
            $this->identity,
            evidence: new AuthenticationEvidence(['test.second']),
        );
    }
}

final class CapturingHandlerFixture implements RequestHandlerInterface
{
    public ?IdentityInterface $identity = null;

    public function handle(
        ServerRequestInterface $request,
    ): ResponseInterface {
        $identity = $request->getAttribute(IdentityInterface::class);
        $this->identity = $identity instanceof IdentityInterface
            ? $identity
            : null;

        return new Response(204);
    }
}

final class ChainedIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
