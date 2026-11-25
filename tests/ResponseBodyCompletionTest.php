<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Tests;

use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Middleware\InvalidPayloadMiddleware;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ResponseBodyCompletionTest extends TestCase
{
    /** @return iterable<string, array{string, int}> */
    public static function successfulWrites(): iterable
    {
        foreach (['denied', 'invalid-payload'] as $endpoint) {
            yield $endpoint . ' full write' => [$endpoint, PHP_INT_MAX];
            yield $endpoint . ' partial writes' => [$endpoint, 3];
        }
    }

    #[DataProvider('successfulWrites')]
    public function testErrorResponseContainsTheCompleteJson(string $endpoint, int $chunkBytes): void
    {
        $response = $this->respond($endpoint, $this->responses($chunkBytes));

        self::assertSame($endpoint === 'denied' ? 401 : 400, $response->getStatusCode());
        self::assertSame(
            $endpoint === 'denied'
                ? ['error' => 'unauthorized']
                : ['error' => 'invalid_payload', 'field' => 'Authorization'],
            json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR),
        );
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    /** @return iterable<string, array{string, int}> */
    public static function stalledWrites(): iterable
    {
        foreach (['denied', 'invalid-payload'] as $endpoint) {
            yield $endpoint . ' no initial progress' => [$endpoint, 0];
            yield $endpoint . ' stalls after partial write' => [$endpoint, 3];
        }
    }

    #[DataProvider('stalledWrites')]
    public function testIncompleteErrorResponseCannotBeReturned(string $endpoint, int $chunkBytes): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not write a complete authentication response.');

        $this->respond($endpoint, $this->responses($chunkBytes, true));
    }

    private function respond(string $endpoint, ResponseFactoryInterface $responses): ResponseInterface
    {
        if ($endpoint === 'denied') {
            return (new DeniedResponseFactory($responses))->create(new Unauthorized());
        }

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willThrowException(InvalidPayloadException::invalidField('Authorization'));

        return (new InvalidPayloadMiddleware($responses))->process(new ServerRequest('GET', '/'), $handler);
    }

    private function responses(int $chunkBytes, bool $stallAfterFirstWrite = false): ResponseFactoryInterface
    {
        $body = '';
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $bytes) use ($chunkBytes, $stallAfterFirstWrite, &$body): int {
                if ($stallAfterFirstWrite && $body !== '') return 0;
                $written = min($chunkBytes, strlen($bytes));
                $body .= substr($bytes, 0, $written);

                return $written;
            },
        );
        $stream->method('__toString')->willReturnCallback(static function () use (&$body): string { return $body; });
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturnCallback(
            static fn(int $status): ResponseInterface => new Response($status, [], $stream),
        );

        return $responses;
    }
}
