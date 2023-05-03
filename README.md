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
## configuration

---

### config.allow

(array) static allow rules

#### default

```json
[]
```

#### examples

allow requests to all hosts from private networks

```json
[
  {
    "cidr": "10.0.0.0/8"
  },
  {
    "cidr": "192.168.0.0/16"
  }
]
```

---

### config.asset_path

(string) Directory containing static assets for the application

#### default

```json
"/usr/local/share/doorbell"
```

---

### config.base_url

(string) External URL for the application (used to generate hyperlinks)

#### default

```json
"http://127.0.0.1"
```

---

### config.cache_size

(integer) Dictates the number of items kept in the application's LRU cache

#### default

```json
1000
```

---

### config.deny

(array) static deny rules

#### default

```json
[]
```

#### examples

deny requests from a pesky bot

```json
[
  {
    "ua": "Super Duper Crawler v1.0"
  }
]
```

---

### config.geoip_asn_db

(string) Path to GeoIP ASN database (.mmdb file)

---

### config.geoip_city_db

(string) Path to GeoIP City database (.mmdb file)

---

### config.geoip_country_db

(string) Path to GeoIP Country database (.mmdb file)

---

### config.host

(string) Server Hostname

---

### config.log_path

(string) Path to the directory where log files will be stored

#### default

```json
"/var/log/doorbell"
```

---

### config.metrics

(object) Application metrics configuration

---

### config.metrics.disable

(boolean) Disable all instrumentation and metrics collection

#### default

```json
false
```

---

### config.metrics.interval

(number) How often (in seconds) to measure and evaluate things

#### default

```json
5
```

---

### config.notify

(object) Notification subsystem configuration

#### examples

explicitly disable notifications

```json
{
  "strategy": "none"
}
```

---

### config.notify.config

(object) Provider-specific configuration

---

### config.notify.periods

(array) Time periods when notifications can be sent

#### examples

send notifications between 9pm and midnight

```json
[
  {
    "from": 21
  }
]
```

send notifications between 8am and 6pm

```json
[
  {
    "from": 8,
    "to": 18
  }
]
```

send notifactions between 9am-1pm and 8pm-10pm

```json
[
  {
    "from": 9,
    "to": 13
  },
  {
    "from": 20,
    "to": 22
  }
]
```

send notifactions between 11pm and 3am

```json
[
  {
    "from": 23,
    "to": 0
  },
  {
    "from": 0,
    "to": 3
  }
]
```

---

### config.notify.strategy

(string) Notification provider

#### default

```json
"none"
```

---

### config.ota

(object) OTA configuration

#### examples

update rules from https://foo.com/rules.json every 15 minutes

```json
{
  "interval": 900,
  "url": "https://foo.com/rules.json"
}
```

sending additional headers with the request

```json
{
  "headers": {
    "Accept": "application/json"
  },
  "url": "https://foo.com/rules"
}
```

---

### config.ota.headers

(object) Headers that will be sent with update requests

---

### config.ota.interval

(number) How often (in seconds) to check for remote updates

#### default

```json
60
```

---

### config.ota.url

(string) URL to remote rules list

---

### config.runtime_path

(string) Directory for NGINX-related files (and the default state path)

#### default

```json
"/var/run/doorbell"
```

---

### config.state_path

(string) State directory, where rules and stat data are persisted

#### default

```json
"/var/run/doorbell"
```

---

### config.trusted

(array) Trusted IP addresses/CIDR ranges

#### default

```json
[
  "127.0.0.1/32"
]
```

#### examples

trust localhost and two private networks

```json
[
  "127.0.0.1",
  "10.0.3.1",
  "10.0.4.0/24"
]
```

trust localhost only

```json
[
  "127.0.0.1"
]
```

---

### config.unauthorized

(string) How to handle incoming requests that don't match a rule

#### default

```json
"return-401"
```

## rules

---

### rule.action

(string) Action to take when the rule matches a request

---

### rule.addr

(string) Client IP address of the request

#### examples

IPv4

```json
"1.2.3.4"
```

IPv6

```json
"2607:f8b0:400a:800::200e"
```

---

### rule.asn

(integer) Network ASN

---

### rule.cidr

(string) Subnet (in CIDR notation)

#### examples

match IPv4 addresses 1.2.3.0-1.2.3.255

```json
"1.2.3.0/24"
```

---

### rule.comment

(string) An informative comment about the rule

---

### rule.conditions

(integer) (generated) number of match conditions a rule has

---

### rule.country

(string) Country code of the request

---

### rule.created

(number) A Unix epoch timestamp of when the rule was created

---

### rule.deny_action

(string) Specific action to take when the rule matches a request and the action is 'deny'

---

### rule.expires

(number) Absolute timestamp (as a Unix epoch) that dictates when the rule expires

---

### rule.hash

(string) (generated) hash of a rule's match conditions

---

### rule.host

(string) Request Host header

---

### rule.id

(string) Universally unique identifier (UUID) for this rule

---

### rule.method

(string) Request HTTP method

---

### rule.org

(string) Network Org

---

### rule.path

(string) Request path

#### examples

match '/foo' exactly

```json
"/foo"
```

match paths that start with '/foo'

```json
"~^/foo/.+"
```

---

### rule.source

(string) Origin of the rule

---

### rule.terminate

(boolean) If `true`, do not attempt to match any other rules after this one

---

### rule.ttl

(number) Relative timestamp (in seconds) of the rule's expiration

---

### rule.ua

(string) Request User-Agent header

#### examples

match 'my specific user agent' exactly

```json
"my specific user agent"
```

regex match

```json
"~.*my regex user agent match version: [0-9]+.*"
```

