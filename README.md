# Componenta Auth HTTP

PSR-7/PSR-15 integration for Componenta Auth 3.

Owns HTTP payload extraction/storage, request-scoped credential publication,
generic authentication middleware and denial responses. Concrete authentication
mechanisms such as sessions, OTP, password, remember-me and JWT live in their
own packages.

## Credential publication lifecycle

`CredentialTransportState` belongs to one request. Authentication middleware
shares it with downstream components and the middleware that created it applies
the final decision to the response. Discard callbacks compensate credentials
that were issued but not successfully published.

`discardQueued()` cancels pending work. During publication,
`ReplacingPayloadStorage` may discard newer pending work without cancelling the
batch already being published. `clear()` is a terminal removal decision: it also
cancels an in-flight batch if a storage or response callback requests logout.
The response then removes all registered credentials, and subsequent queueing
cannot restore them for that request.

Compensation callbacks run once in reverse registration order. All callbacks in
each compensation pass are attempted even when one fails; that pass's first
cleanup failure propagates, including when it supersedes a publication failure.
A later pass for the active batch can supersede a failure from a nested clear of
pending work. Successful publication releases the batch's compensation callbacks
without invoking them.
