<?php
declare(strict_types=1);
namespace Componenta\Auth\Http;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
final class CredentialTransportState
{
    /** @var array<int, PayloadStorageInterface> */
    private array $storages = [];
    /** @var list<array{storage: PayloadStorageInterface, payload: object}> */
    private array $queued = [];
    /** @var list<\Closure(): void> */
    private array $discardCallbacks = [];
    private bool $clear = false;
    public bool $empty { get => !$this->clear && $this->queued === []; }
    public bool $cleared { get => $this->clear; }
    /** @return array{storages:string, queued:string, discardCallbacks:string, cleared:bool} */
    public function __debugInfo(): array
    {
        return [
            'storages' => '[REDACTED]',
            'queued' => '[REDACTED]',
            'discardCallbacks' => '[REDACTED]',
            'cleared' => $this->clear,
        ];
    }
    public function register(PayloadStorageInterface $storage): void { $this->storages[spl_object_id($storage)] = $storage; }
    public function queue(PayloadStorageInterface $storage, object $payload): void
    {
        $this->register($storage);
        if (!$this->clear) $this->queued[] = ['storage' => $storage, 'payload' => $payload];
    }
    public function onDiscard(#[\SensitiveParameter] \Closure $callback): void
    {
        if ($this->clear) { $callback(); return; }
        $this->discardCallbacks[] = $callback;
    }
    public function discardQueued(): void
    {
        $this->queued = [];
        $callbacks = array_reverse($this->discardCallbacks);
        $this->discardCallbacks = [];
        $failure = null;
        foreach ($callbacks as $callback) {
            try { $callback(); } catch (\Throwable $exception) { $failure ??= $exception; }
        }
        if ($failure !== null) throw $failure;
    }
    /** Makes credential removal terminal for this request, including in-flight publication. */
    public function clear(#[\SensitiveParameter] PayloadStorageInterface $storage): void
    {
        $this->register($storage); $this->clear = true; $this->discardQueued();
    }
    public function apply(
        #[\SensitiveParameter] ServerRequestInterface $request,
        #[\SensitiveParameter] ResponseInterface $response,
    ): ResponseInterface {
        if ($this->clear) {
            $removed = [];
            do {
                foreach ($this->storages as $id => $storage) {
                    if (isset($removed[$id])) continue;
                    $removed[$id] = true;
                    $response = $storage->remove($request, $response);
                }
                $response = CredentialResponseHeaders::apply($response);
                // Removal and header callbacks may register another transport.
            } while (count($removed) !== count($this->storages));

            return $response;
        }
        if ($this->queued === []) return $response;
        // Once publication starts, replacement concerns pending work, not
        // the batch currently being committed and its compensation callbacks.
        $queued = $this->queued;
        $discardCallbacks = $this->discardCallbacks;
        $this->queued = [];
        $this->discardCallbacks = [];
        try {
            foreach ($queued as $entry) {
                $response = $entry['storage']->store($request, $response, $entry['payload']);
                if ($this->cleared) break;
            }
            if (!$this->cleared) $response = CredentialResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            $this->discardCallbacks = [...$discardCallbacks, ...$this->discardCallbacks];
            $this->discardQueued();
            throw $exception;
        }
        // A terminal clear may arrive through a storage or response callback.
        // It cancels the active batch too, unlike replacement of pending work.
        if ($this->cleared) {
            $this->discardCallbacks = [...$discardCallbacks, ...$this->discardCallbacks];
            $this->discardQueued();

            return $this->apply($request, $response);
        }

        return $response;
    }
}
