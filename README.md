# doorbell

![CI](https://github.com/flrgh/doorbell/actions/workflows/test.yml/badge.svg)

## Description

_A forward auth server for the rest of us._

## The What and the Why

I self-host a bunch of applications on a home server, many of which I want to be available from the WAN. Historically this involves some frustrating push/pull between security and convenience:

1. Deployed webapps are heterogenous, with varying security features
2. L7 access controls are a dealbreaker for many types of clients. I can't one of the many Jellyfin clients to support my bespoke oauth setup in order to talk to the media server.
3. L4 access controls are inconvenient when on-the-go and sometimes not granular enough.

Doorbell is the solution. At its core it is an access control engine. Doorbell can:

* Allow/deny access purely based on L4 request properties:
  * Source IP/Network
  * GeoIP Country Code
  * GeoIP ASN/Org
* Allow/deny access based on fine-grained L7 request properties:
  * `Host` header
  * `User-Agent` header
  * Request Path
  * Request Method

What makes Doorbell convenient is how access control policies ("rules") are managed. Rules can be managed via static configuration, web UI, and HTTP API. This makes it easy to do things like...

* Grant temporary access to an application for my current IP address via an expiring rule
* Allow public access to `/.well-known/acme-challenge/*` for Let's Encrypt challenges on all applications while keeping everything else locked down
* Receive a push notification when a friend is trying to access the server and quickly grant them access

## Status

Doorbell has been fulfilling its purpose of protecting my home server for over two years now.

## How it Works

Doorbell's forward auth endpoint is server/proxy-agnostic and can be used with a variety of proxies, but development currently targets [traefik](https://github.com/traefik/traefik) for its [ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) middleware feature (because that is what I use at home).

Upon receiving a request, the proxy makes a request to Doorbell's `/ring` endpoint, supplying all of the proper `X-Forwarded-*` headers to inform Doorbell of the incoming request:

```
GET /ring HTTP/1.1
Host: doorbell
user-agent: curl/7.85.0
x-forwarded-for: 1.2.3.4
x-forwarded-host: my-application
x-forwarded-proto: https
x-forwarded-method: GET
x-forwarded-uri: /a/b/c?d=1&e=2
accept: */*
```

If the request matches a known `allow` rule, it responds with a `200`

If the request matches a known `deny` rule, it responds with a `403`

If the request matches no known rule, the unauthorized policy takes over. This is configurable, but it can follow a couple different flows:

* Respond immediately with a `401` status code
* Send an access request push notification and block until access is granted
* Redirect the client to a different endpoint where they must authenticate (via other means) in order to add an `allow` rule

## License

This module is licensed under the BSD license.

Copyright (C) 2021-2024, by Michael Martin <flrgh@protonmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
