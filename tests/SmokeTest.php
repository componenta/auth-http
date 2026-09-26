<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Extractor\BearerExtractor;
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

final class SmokeTest extends TestCase
{
    public function testBearerExtractorRedactsCredential(): void
    {
        $payload = (new BearerExtractor())->extract(
            (new ServerRequest('GET', '/'))
                ->withHeader('Authorization', 'Bearer abc.DEF'),
        );

        self::assertNotNull($payload);
        self::assertStringNotContainsString(
            'abc.DEF',
            json_encode($payload, JSON_THROW_ON_ERROR),
        );
    }

    public function testMiddlewareDiscardsOwnedTransportStateWhenAuthenticatorThrows(): void
    {
        $counter = (object) ['discarded' => 0];
        $extractor = new class implements PayloadExtractorInterface {
            public function extract(
                ServerRequestInterface $request,
            ): ?object {
                return new \stdClass();
            }
        };
        $authenticator = new class($counter) implements AuthenticatorInterface {
            public function __construct(private object $counter) {}

            public function attempt(
                object $payload,
                ContextInterface $context,
            ): AuthenticationResult {
                $transportState = $context->getAttribute(
                    CredentialTransportState::class,
                );
                \PHPUnit\Framework\Assert::assertInstanceOf(
                    CredentialTransportState::class,
                    $transportState,
                );
                $counter = $this->counter;
                $transportState->onDiscard(
                    static function () use ($counter): void {
                        ++$counter->discarded;
                    },
                );

                throw new \RuntimeException('authentication failed');
            }
        };
        $handler = new class implements RequestHandlerInterface {
            public function handle(
                ServerRequestInterface $request,
            ): ResponseInterface {
                throw new \LogicException(
                    'Downstream handler must not run.',
                );
            }
        };

        try {
            (new AuthenticationMiddleware($extractor, $authenticator))
                ->process(new ServerRequest('GET', '/'), $handler);
            self::fail('Authenticator exception must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('authentication failed', $exception->getMessage());
        }

        self::assertSame(1, $counter->discarded);
    }

    public function testMiddlewarePublishesTypedState(): void
    {
        $identity = new SmokeIdentity();
        $state = new SmokeAuthenticationState();
        $extractor = new class implements PayloadExtractorInterface {
            public function extract(
                ServerRequestInterface $request,
            ): ?object {
                return new \stdClass();
            }
        };
        $authenticator = new class($identity, $state) implements
            AuthenticatorInterface {
            public function __construct(
                private IdentityInterface $identity,
                private AuthenticationStateInterface $state,
            ) {}

            public function attempt(
                object $payload,
                ContextInterface $context,
            ): AuthenticationResult {
                \PHPUnit\Framework\Assert::assertInstanceOf(
                    CredentialTransportState::class,
                    $context->getAttribute(CredentialTransportState::class),
                );

                return new AuthenticationResult(
                    $this->identity,
                    state: $this->state,
                    evidence: new AuthenticationEvidence(['session']),
                );
            }
        };
        $seen = null;
        $handler = new class($seen) implements RequestHandlerInterface {
            public function __construct(
                private ?ServerRequestInterface &$seen,
            ) {}

            public function handle(
                ServerRequestInterface $request,
            ): ResponseInterface {
                $this->seen = $request;

                return new Response(204);
            }
        };

        (new AuthenticationMiddleware($extractor, $authenticator))
            ->process(new ServerRequest('GET', '/'), $handler);

        self::assertInstanceOf(ServerRequestInterface::class, $seen);
        self::assertSame(
            $state,
            $seen->getAttribute(AuthenticationStateInterface::class),
        );
        self::assertSame($state, $seen->getAttribute($state::class));
    }
}

final class SmokeIdentity implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final class SmokeAuthenticationState implements AuthenticationStateInterface
{
}
