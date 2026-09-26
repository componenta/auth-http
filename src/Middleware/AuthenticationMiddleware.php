<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Authenticates and commits one shared request-scoped transport decision. */
final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private PayloadExtractorInterface $extractor,
        private AuthenticatorInterface $authenticator,
        private ?PayloadStorageInterface $storage = null,
    ) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        if (
            $request->getAttribute(DeniedReasonInterface::class)
                instanceof DeniedReasonInterface
        ) {
            return $handler->handle($request);
        }

        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $handler->handle($request);
        }

        $existingIdentity = $request->getAttribute(IdentityInterface::class);
        $existingAuthState = $request->getAttribute(
            AuthenticationStateInterface::class,
        );
        $existingTransportState = $request->getAttribute(
            CredentialTransportState::class,
        );
        $ownsTransportState = !$existingTransportState
            instanceof CredentialTransportState;
        $transportState = $ownsTransportState
            ? new CredentialTransportState()
            : $existingTransportState;

        if ($this->storage !== null) {
            $transportState->register($this->storage);
        }

        $request = $request->withAttribute(
            CredentialTransportState::class,
            $transportState,
        );

        try {
            $result = $this->authenticator->attempt($payload, new Context([
                ServerRequestInterface::class => $request,
                ContextInterface::EXTRACTOR => $this->extractor,
                CredentialTransportState::class => $transportState,
            ]));
        } catch (\Throwable $exception) {
            if ($ownsTransportState) {
                $transportState->discardQueued();
            }

            throw $exception;
        }

        if (
            $result->subject instanceof IdentityInterface
            && $existingIdentity instanceof IdentityInterface
            && !$result->subject->uuid->equals($existingIdentity->uuid)
        ) {
            $transportState->discardQueued();
            $result = new AuthenticationResult(new InvalidCredentials());
        }

        if ($result->subject instanceof DeniedReasonInterface) {
            $transportState->discardQueued();
        } elseif ($result->transportPayload !== null) {
            if ($this->storage === null) {
                $transportState->discardQueued();

                throw new \LogicException(
                    'Authentication credential mutation requires a PayloadStorageInterface before downstream execution.',
                );
            }

            $transportState->queue(
                $this->storage,
                $result->transportPayload,
            );
        }

        $request = $request
            ->withoutAttribute(IdentityInterface::class)
            ->withoutAttribute(DeniedReasonInterface::class)
            ->withoutAttribute(AuthenticationStateInterface::class);

        if ($existingAuthState instanceof AuthenticationStateInterface) {
            $request = $request->withoutAttribute(
                $existingAuthState::class,
            );
        }

        if ($result->subject instanceof IdentityInterface) {
            $request = $request->withAttribute(
                IdentityInterface::class,
                $result->subject,
            );
            $state = $result->state;

            if (
                $state === null
                && $existingIdentity instanceof IdentityInterface
                && $existingIdentity->uuid->equals($result->subject->uuid)
                && $existingAuthState instanceof AuthenticationStateInterface
            ) {
                $state = $existingAuthState;
            }

            if ($state !== null) {
                $request = $request
                    ->withAttribute(AuthenticationStateInterface::class, $state)
                    ->withAttribute($state::class, $state);
            }
        } else {
            $request = $request->withAttribute(
                DeniedReasonInterface::class,
                $result->subject,
            );
        }

        try {
            $response = $handler->handle($request);
        } catch (\Throwable $exception) {
            if ($ownsTransportState) {
                $transportState->discardQueued();
            }

            throw $exception;
        }

        if (!$ownsTransportState || $transportState->empty) {
            return $response;
        }

        return $transportState->apply($request, $response);
    }
}
