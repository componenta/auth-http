<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Auth\Http\Extractor\BearerExtractor;
use Componenta\Auth\Http\Middleware\InvalidPayloadMiddleware;
use Componenta\Auth\Http\Middleware\RequireAuthenticationMiddleware;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CredentialTraceRedactionTest extends TestCase
{
    private const string SECRET = 'synthetic-http-secret-marker';

    /** @return iterable<string, array{string, class-string, string, int}> */
    public static function boundaries(): iterable
    {
        yield 'bearer extraction' => ['bearer', BearerExtractor::class, 'extract', 1];
        yield 'credential replacement' => ['store', ReplacingPayloadStorage::class, 'store', 3];
        yield 'credential removal' => ['remove', ReplacingPayloadStorage::class, 'remove', 2];
        yield 'required authentication' => ['require', RequireAuthenticationMiddleware::class, 'process', 2];
        yield 'invalid payload middleware' => ['invalid', InvalidPayloadMiddleware::class, 'process', 2];
        yield 'denial response' => ['denied', DeniedResponseFactory::class, 'create', 1];
    }

    #[DataProvider('boundaries')]
    public function testCredentialArgumentsAreRedactedFromBoundaryExceptionFrames(
        string $boundary,
        string $class,
        string $method,
        int $argumentCount,
    ): void {
        $previous = ini_set('zend.exception_ignore_args', '0');
        self::assertNotFalse($previous);

        try {
            $failure = null;
            try {
                $this->callBoundary($boundary);
            } catch (\RuntimeException $exception) {
                $failure = $exception;
            }

            self::assertInstanceOf(\RuntimeException::class, $failure);
            $frames = array_values(array_filter(
                $failure->getTrace(),
                static fn(array $frame): bool => ($frame['class'] ?? null) === $class
                    && $frame['function'] === $method,
            ));
            self::assertCount(1, $frames);

            for ($index = 0; $index < $argumentCount; ++$index) {
                self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][$index]);
            }
            self::assertStringNotContainsString(self::SECRET, print_r($frames[0], true));
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    private function callBoundary(string $boundary): void
    {
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('Authorization', 'Bearer ' . self::SECRET . '!');
        $response = new Response(200, ['Set-Cookie' => 'credential=' . self::SECRET]);
        $payload = (object) ['credential' => self::SECRET];
        $reason = new readonly class(self::SECRET) implements DeniedReasonInterface {
            public string $code;
            public array $attributes;
            public function __construct(string $secret)
            {
                $this->code = 'custom_denial';
                $this->attributes = ['trusted-audit-secret' => $secret];
            }
        };
        $responses = new class implements ResponseFactoryInterface {
            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface
            {
                throw new \RuntimeException('Response creation failed.');
            }
        };
        $handler = new class(self::SECRET) implements RequestHandlerInterface {
            public function __construct(private string $capturedSecret) {}
            public function handle(#[\SensitiveParameter] ServerRequestInterface $request): ResponseInterface
            {
                throw new \RuntimeException('Handler failed.');
            }
        };
        $storage = new class implements PayloadStorageInterface {
            public function store(
                #[\SensitiveParameter] ServerRequestInterface $request,
                #[\SensitiveParameter] ResponseInterface $response,
                #[\SensitiveParameter] object $payload,
            ): ResponseInterface {
                throw new \RuntimeException('Store failed.');
            }
            public function remove(
                #[\SensitiveParameter] ServerRequestInterface $request,
                #[\SensitiveParameter] ResponseInterface $response,
            ): ResponseInterface {
                throw new \RuntimeException('Removal failed.');
            }
        };

        match ($boundary) {
            'bearer' => (new BearerExtractor())->extract($request),
            'store' => (new ReplacingPayloadStorage($storage))->store($request, $response, $payload),
            'remove' => (new ReplacingPayloadStorage($storage))->remove($request, $response),
            'require' => (new RequireAuthenticationMiddleware(new DeniedResponseFactory($responses)))->process($request, $handler),
            'invalid' => (new InvalidPayloadMiddleware($responses))->process($request, $handler),
            'denied' => (new DeniedResponseFactory($responses))->create($reason),
        };
    }
}
