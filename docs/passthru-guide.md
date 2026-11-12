# Carrying your own protocol through the router: a guide to payload passthru

This guide explains how to use WAMP's Payload Passthru Mode (`ppt_*`) to move a payload in your own format (protobuf, FlatBuffers, a hand-packed binary envelope, encrypted data) through this router. The
reference description of what the router does is in the README ("Payload passthru"); this page is about how to *use* it. Nothing here needs changes to the router, and no example program ships with it:
the snippets show the shape of the code, with the encoding and decoding functions left to you.

## 1. What it is for, and what it is not

Normally a WAMP message carries arguments the router could read: strings, numbers, lists, dictionaries. Passthru marks one message as carrying a single opaque blob that the router must not interpret. The router still
**routes** it (by topic or procedure URI), **authorizes** it (by role rules), **meters** it (rate limits, queue limits, backpressure) and **delivers** it unchanged. It never parses, validates, transforms or stores the blob.

Use it when:

- the payload is in a format the router has no schema for (protobuf, FlatBuffers, Cap'n Proto, a vendor envelope), and you do not want to translate it to WAMP lists and dictionaries and back;
- the payload is encrypted end to end and only the endpoints hold the key;
- the payload is a large opaque blob (a file chunk, an image) and you want it to cross the router byte for byte.

It is **not** a gateway. Every client still speaks WAMP to the router, over RawSocket or WebSocket, with CBOR, JSON or MessagePack. The router does not translate HTTP, gRPC or MQTT, and it cannot route on the
content of the blob (put what routing needs in the topic or procedure URI).

## 2. The contract

| | |
|---|---|
| Options (on PUBLISH, CALL, and on the callee's YIELD) | `ppt_scheme` (required, non-empty string); `ppt_serializer`, `ppt_cipher`, `ppt_keyid` (optional strings) |
| Payload | exactly one argument, of binary type, and no keyword arguments |
| What the router adds | nothing: the `ppt_*` options are copied unchanged into the EVENT, INVOCATION or RESULT `details`, and the blob into its arguments |
| What it checks | the shape above; that the sender announced the feature; optionally that the role may use that `ppt_scheme` |
| Feature name | `payload_passthru_mode`, announced in the `features` of your HELLO roles; the router announces it for `broker` and `dealer` |

Anything else in the options is the router's business as usual (`acknowledge`, `exclude_me`, `timeout`, `receive_progress`). The four `ppt_*` options have no meaning to the router beyond being copied.

## 3. Designing your scheme

The four options are the metadata a receiver needs to decode the blob. The router never looks at them, so the meaning is yours to define. A convention that works:

- **`ppt_scheme`**: the name of *your protocol and its version*, for example `x_sensor_v1` or `x_orders_pb_v2`. The `x_` prefix keeps private schemes apart from names the WAMP spec may define later. Put the version in the
  name: when the schema changes incompatibly, publish a new scheme name and let old receivers ignore it, rather than guessing from the bytes.
- **`ppt_serializer`**: what the bytes are (`protobuf`, `flatbuffers`, `cbor`, `custom`), if the scheme name does not already say so.
- **`ppt_cipher`** and **`ppt_keyid`**: only for encrypted payloads. `ppt_cipher` names the algorithm (`aes-256-gcm`, `xsalsa20poly1305`), `ppt_keyid` says which key to use, so keys can be rotated.

Two rules of thumb. The schema belongs to the clients: the router needs none of it, which is the point. And the options are **not secret**: the router reads them (it checks `ppt_scheme`) and copies them into every
EVENT, INVOCATION and RESULT. Put identifiers in them, never keys.

## 4. Walkthrough: a binary protocol over RPC

A fleet service answers queries about devices. Requests and responses are protobuf messages; the router should not care.

```
analytics client                      router                         fleet service
      |  CALL  options={ppt_scheme:"x_fleet_pb_v1", ppt_serializer:"protobuf"}  |
      |  procedure="fleet.query", arguments=[<QueryRequest bytes>]              |
      |------------------------------>|                                         |
      |                               | INVOCATION details={ppt_scheme:..,      |
      |                               |   ppt_serializer:..}, arguments=[bytes] |
      |                               |---------------------------------------->|
      |                               |  YIELD options={ppt_scheme:..}          |
      |                               |  arguments=[<QueryResponse bytes>]      |
      |                               |<----------------------------------------|
      |  RESULT details={ppt_scheme:..,  ppt_serializer:..}, arguments=[bytes]  |
      |<------------------------------|                                         |
```

The callee (the fleet service) with this repository's C++ client:

```cpp
WampClient service{io};                       // announces the feature by default (set_passthru(false) to turn it off)
co_await service.connect("router.example", 8080, "fleet");

co_await service.register_procedure("fleet.query",
    [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
        // details carry the ppt_* options exactly as the caller sent them
        const auto& scheme = std::get<std::string>(inv.details.at("ppt_scheme"));
        const auto& request_bytes = std::get<WampBytes>(inv.arguments.at(0));

        WampBytes response_bytes = handle_query(scheme, request_bytes);   // your decode, work, encode

        // the answer is passthru too: same shape, options on the YIELD
        co_return YieldMessage{inv.request_id,
                               WampDict{{"ppt_scheme", scheme}, {"ppt_serializer", std::string{"protobuf"}}},
                               WampList{std::move(response_bytes)}};
    });
```

The caller:

```cpp
WampClient analytics{io};
co_await analytics.connect("router.example", 8080, "fleet");

WampBytes request = encode_query(device_id);                              // your encode
auto result = co_await analytics.call_result(
    "fleet.query", WampList{request}, {}, std::chrono::milliseconds{0},
    WampDict{{"ppt_scheme", std::string{"x_fleet_pb_v1"}}, {"ppt_serializer", std::string{"protobuf"}}});

const auto& response = std::get<WampBytes>(result.arguments.at(0));       // result.details has the ppt_* options
auto reply = decode_response(response);
```

What the router did in between: checked that both messages had a non-empty `ppt_scheme` and exactly one binary argument, checked that the callee had announced the feature, copied the options into `details`, and
forwarded. If the callee had not announced the feature the caller would have got `wamp.error.feature_not_supported` instead of the call reaching it.

Errors from the callee (`ERROR` replies) are ordinary WAMP errors and may carry their own arguments; they are not part of passthru.

## 5. Walkthrough: pub/sub

Sensors publish readings in a compact binary envelope; any number of services subscribe.

```cpp
WampBytes reading = pack_reading(sensor_id, timestamp, values);           // your envelope
co_await sensor.publish("fleet.readings", WampList{reading}, {}, /*acknowledge=*/false, /*exclude_me=*/true,
                        WampDict{{"ppt_scheme", std::string{"x_sensor_v1"}}});

co_await service.subscribe("fleet.readings", [](const EventMessage& event) {
    const auto& scheme = std::get<std::string>(event.details.at("ppt_scheme"));
    if (scheme != "x_sensor_v1") return;                                  // a version you do not know: skip it
    handle_reading(std::get<WampBytes>(event.arguments.at(0)));
});
```

A passthru PUBLISH is delivered **only to subscribers that announced the feature**; the others are skipped without an error (a plain PUBLISH reaches everyone). That has a practical consequence when you migrate a
topic to passthru: first upgrade and announce on the subscriber side, then switch the publishers, otherwise old subscribers silently stop receiving. The publisher itself must have announced the feature too,
otherwise its PUBLISH is refused (`wamp.error.feature_not_supported`, delivered only if it asked for `acknowledge`, since an unacknowledged PUBLISH never gets a reply).

Prefix and wildcard subscriptions work as for any event: the blob arrives with `details.topic` as well as the `ppt_*` entries.

## 6. Walkthrough: end-to-end encryption

The router is a good place to *not* have the key. Clients encrypt the application payload and carry the ciphertext as the blob:

1. The publisher serializes its message (any format), encrypts it with a key shared with the intended readers, and sends `ciphertext` as the single binary argument with
   `ppt_scheme = "x_secure_v1"`, `ppt_cipher = "aes-256-gcm"` and `ppt_keyid = "2026-11"`. The nonce/IV and the authentication tag travel inside the blob, in a layout your scheme defines.
2. Subscribers read `ppt_keyid`, look the key up in their own store, decrypt and verify, then decode.
3. **Key rotation** is a new `ppt_keyid`: publishers switch to the new id, subscribers accept both until the old one has drained. The router needs no change.

What the router still sees: the topic or procedure URI, the sizes and timing of messages, who sent them (their session and role) and the `ppt_*` metadata. What it cannot do: read or alter the content without the
receivers noticing (with an authenticated cipher), or route on the content. Authorization therefore has to be expressed in terms of topics and schemes, which is what `ppt_schemes` is for (section 7).

Key distribution is outside WAMP and outside this router.

## 7. Operating it

- **Announcing support.** A client says it can do passthru in the `features` of its HELLO roles (`payload_passthru_mode: true`); the C++ client does it by default (`set_passthru(false)` turns it off). A session that did
  not announce it cannot send `ppt_*` and does not receive passthru events or invocations.
- **Errors you may see.**
  - `wamp.error.feature_not_supported`: the sender did not announce the feature, or a CALL's callee did not.
  - `wamp.error.invalid_argument`: `ppt_scheme` missing or empty, a `ppt_*` option that is not a string, or a payload that is not exactly one binary argument (a text or list argument, two arguments, or keyword
    arguments all fail). For a callee's YIELD the *caller* receives this error.
  - `wamp.error.not_authorized`: the role does not allow that scheme (below).
- **Restricting schemes per role.** In the configuration, `[roles.<name>] ppt_schemes = ["x_sensor_v1"]` limits which `ppt_scheme` values that role may use in PUBLISH and CALL; without it any scheme is allowed.
  This lets you say "sensors may only publish `x_sensor_v1`".
- **Size.** The blob is limited by the transport message size: 16,777,215 bytes at most (`[server.websocket] max_message_size` can lower it for WebSocket). Large transfers should be chunked by the application.
- **Serializers.** The blob is a byte string in CBOR and MessagePack. In JSON it is a string that starts with a NUL character followed by base64 (`"\u0000AQID"`), as the WAMP spec defines, so JSON and binary clients
  can exchange passthru messages. Sending a plain JSON string as the payload is rejected as `invalid_argument`.
- **Several router threads.** Nothing changes; passthru events and invocations cross shards like any other, and the check that a subscriber or callee announced the feature happens on the shard that owns it.
- **Progressive results.** Partial results (`progress`) may carry passthru payloads too; each is validated like a final one, except that a malformed partial is dropped with a warning instead of ending the call.
- **Debugging.** A callee's YIELD that fails the shape check is logged at warn level (`has malformed passthru options or payload`) and reaches the caller as `invalid_argument`. Refused PUBLISH and CALL are visible to
  the sender as errors (PUBLISH only with `acknowledge`). A subscriber that did not announce the feature is skipped silently, so "my subscriber gets nothing" usually means it did not announce.

## 8. Checklist and pitfalls

- The payload is **one** argument of binary type. Not a string, not a list, not in keyword arguments.
- Announce the feature on both sides, for every role that sends or receives passthru messages.
- Put the schema version in `ppt_scheme`; the router will not tell you a receiver cannot decode a new version.
- Keep keys and secrets out of the `ppt_*` options.
- Route on the URI. If a receiver needs to pick messages by a field inside the blob, expose that field as part of the topic (`fleet.readings.eu.temperature`) and use a prefix or wildcard subscription.
- The router does not compress, deduplicate, order beyond normal per-publisher order, or retain passthru messages.
- Check your client library: passthru needs support on the client side, to set the options, announce the feature and read the details. This repository's C++ client (`WampClient`) supports it. Autobahn|Python 24.4
  has no `ppt_*` parameters in its options classes at the time of writing, so a Python client needs a library or a small patch that can send these options and announce the feature.

## 9. What the router will not do

- Translate between protocols or expose HTTP, gRPC or MQTT endpoints.
- Inspect, index, filter or validate the blob, or check it against a schema.
- Decrypt or verify anything.
- Route on the content of the payload.
- Enforce schema evolution or compatibility between publishers and subscribers.

If you need the router to understand some of the data, that data cannot ride in the same message: a message is either passthru (one opaque argument) or not. Put what the router must see in the URI, or send it as a
separate plain message.
