# CapBAC BLS

**Cap**ability-**B**ased **A**ccess **C**ontroll primitives and schemas with BLS aggregated signature. Allows to forge and delegate digital certificates for a simple and crypto-secure transfer of capabilities from one actor to another. This implementation allows all or part of the issued certificates to be revoked without re-issuing crypto-keys. Opening the possibility of precise control of access levels of all actors known to the system.

# Usage

## Maven

``` xml
<dependency>
  <groupId>dev.dotfox</groupId>
  <artifactId>capbac-bls</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>

<repository>
  <id>DotFox</id>
  <url>https://maven.pkg.github.com/DotFox/capbac-bls</url>
  <snapshots>
    <enabled>true</enabled>
  </snapshots>
</repository>

<repository>
  <id>consensys</id>
  <url>https://artifacts.consensys.net/public/maven/maven/</url>
</repository>
```

## Clojure

``` edn
{:deps {dev.dotfox/capbac-bls {:mvn/version "1.0-SNAPSHOT"}}
 :mvn/repos {"DotFox" {:url "https://maven.pkg.github.com/DotFox/capbac-bls"}
             "consensys" {:url "https://artifacts.consensys.net/public/maven/maven/"}}}
```

# Basic primitives

## BLS key-pair (sk, pk)

[Here](https://gist.github.com/paulmillr/18b802ad219b1aee34d773d08ec26ca2) you will find useful links, including a link to the BLS12-381 draft standard used in this implementation.

## CapBACCertificate

A digital certificate signed by all actors who have supplemented or modified the capabilities of the root certificate. Each certificate can contain its own parent, thus forming a chain of certificates.

### Properties

* `issuer` - identifier of the actor responsible for creating this certificate
* `subject` - identifier of the actor to whom this certificate conveys capabilities
* `parent` - optional certificate on the basis of which this certificate was issued
* `expiration` - optional UNIX timestamp after which certificate should be considered expired
* `content_type` - optional string containing media type included as capability
* `capability` - optional byte array with encoded capability granted by that certificate
* `signature` - byte array representing a digital signature certifying that the contents of this certificate have not been altered

## CapBACInvokation

Digital, certificate-based, signed token containing instructions. In conjunction with the included certificate, it forms a complete chain which, when analysed, allows the recipient to decide whether or not to execute the instruction sent with the token.

### Properties

* `invoker` - identifier of the actor requesting to execute the instruction
* `certificate` - certificate issued for the invoker
* `expiration` - optional UNIX timestamp after which certificate should be considered expired
* `content_type` - optional string containing media type included as action
* `action` - byte array with encoded instruction requested by invokation
* `signature` - byte array representing a digital signature certifying that the contents of this invokation have not been altered

## CapBACHolder

The pairing of a personal ID and a secret key. The identifier must be in the form of a URI that uniquely identifies a specific actor. Any actor in the system must be able to retrieve the public key of another actor knowing its identifier.

### Operations

#### `forge`

Allows a CapBACHolder to create a self-signed certificate. The self-signed certificate is used to convey capabilities that the holder possesses. The CapBACHolder creates the certificate by signing its own identity with its private key. The resulting certificate is then issued to itself, and it can be used to represent its own capabilities.

The forge operation can be used to create a basic capability certificate for the CapBACHolder, which can then be used as the basis for more complex certificate chains. This operation provides a way for the CapBACHolder to establish its identity and capabilities within the system.

#### `delegate`

Allows a CapBACHolder to transfer its capabilities to another actor in the system. The capabilities are conveyed through a certificate chain that includes the CapBACHolder's self-signed certificate as well as any other certificates in the chain that the CapBACHolder has received from other actors.

The delegate operation involves creating a new certificate that includes the capabilities being delegated, signed by the CapBACHolder, and then passing this certificate to the recipient. The recipient can then use the certificate to establish its own capabilities within the system.

The delegate operation allows for the transfer of capabilities without the need for the CapBACHolder to reveal its private key or for the recipient to have access to the CapBACHolder's private key. This operation provides a way for CapBACHolder to transfer capabilities to other actors in a secure and controlled manner, while also maintaining the integrity and confidentiality of its own private key.

#### `invoke`

Allows a CapBACHolder to create a signed action based on a certificate with capabilities, which is addressed to another actor in the system. The signed action is intended to convey a specific capability to the recipient and instruct the recipient to perform a particular action. Also the action is cryptographically secure and verifiable, and which can be used to convey specific capabilities to another actor. This operation provides a way for CapBACHolder to control and restrict access to specific capabilities within the system, while also enabling other actors to perform authorized actions based on their capabilities.

## Visualisation

``` text
┌──────────────────┐                      ┌───────────────┐                              ┌───────────────┐                                  ┌────────────┐
│Root certificate: │────────────────────┐ │Certificate 1: │────────────────────────────┐ │Certificate 2: │────────────────────────────────┐ │Invokation: │
└─┬─────────┬──────┘                    │ └─┬─────────┬───┘                            │ └─┬─────────┬───┘                                │ └─┬─────────┬┘
  │Payload: │                           │   │Payload: │                                │   │Payload: │                                    │   │Payload: │
  └─┬───────┴─────────────────────────┐ │   └─┬───────┴─────────────────────────┐      │   └─┬───────┴─────────────────────────────┐      │   └─┬───────┴──────────────────────────────┐
    │issuer: URI(http://host:port/ca) │ │     │issuer: URI(http://host:port/ca) │      │     │issuer: URI(http://host:port/actor1) │      │     │invoker: URI(http://host:port/actor2) │
    ├─────────────────────────────────┤ │     ├─────────────────────────────────┴────┐ │     ├─────────────────────────────────────┴┐     │     ├─────────────┬────────────────────────┘
    │subject: URI(http://host:port/ca)│ │     │subject: URI(http://host:port/actor1) │ │     │subject: URI(http://host:port/actor2) │     └────▶│certificate: │
  ┌─┴─────────┬───────────────────────┘ │     ├────────┬─────────────────────────────┘ │     ├────────┬─────────────────────────────┘           └─┬─────────┬─┘
  │Signature: │                         └────▶│parent: │                               └────▶│parent: │                                           │Payload: │
  └─┬─────────┴─────────────┐                 └─┬──────┴──┐                                  └─┬──────┴──┐                                        └─┬───────┴─────────────────────────────┐
    │BLS.sign(Payload, sk1) │───────┐           │Payload: │                                    │Payload: │                                          │issuer: URI(http://host:port/actor1) │
    └───────────────────────┘       │           └─┬───────┴─────────────────────────┐          └─┬───────┴─────────────────────────┐                ├─────────────────────────────────────┴┐
                                    │             │issuer: URI(http://host:port/ca) │            │issuer: URI(http://host:port/ca) │                │subject: URI(http://host:port/actor2) │
                                    │             ├─────────────────────────────────┤            ├─────────────────────────────────┴────┐           ├────────┬─────────────────────────────┘
                                    │             │subject: URI(http://host:port/ca)│            │subject: URI(http://host:port/actor1) │           │parent: │
                                    │         ┌───┴──────────┬──────────────────────┘            ├────────┬─────────────────────────────┘           └─┬──────┴──┐
                                    │         │capabilities: │                                   │parent: │                                           │Payload: │
                                    │         └─┬────────────┴─┐                                 └─┬──────┴──┐                                        └─┬───────┴─────────────────────────┐
                                    │           │{"id": "qwe"} │                                   │Payload: │                                          │issuer: URI(http://host:port/ca) │
                                    │       ┌───┴───────┬──────┘                                   └─┬───────┴─────────────────────────┐                ├─────────────────────────────────┴────┐
                                    └──────▶│Signature: │                                            │issuer: URI(http://host:port/ca) │                │subject: URI(http://host:port/actor1) │
                                            └─┬─────────┴──────────────────────┐                     ├─────────────────────────────────┤                ├────────┬─────────────────────────────┘
                                              │BLS.agg(BLS.sign(Payload, sk1)) │─────┐               │subject: URI(http://host:port/ca)│                │parent: │
                                              └────────────────────────────────┘     │           ┌───┴──────────┬──────────────────────┘                └─┬──────┴──┐
                                                                                     │           │capabilities: │                                         │Payload: │
                                                                                     │           └─┬────────────┴─┐                                       └─┬───────┴─────────────────────────┐
                                                                                     │             │{"id": "qwe"} │                                         │issuer: URI(http://host:port/ca) │
                                                                                     │       ┌─────┴────────┬─────┘                                         ├─────────────────────────────────┤
                                                                                     │       │capabilities: │                                               │subject: URI(http://host:port/ca)│
                                                                                     │       └─┬────────────┴──┐                                        ┌───┴──────────┬──────────────────────┘
                                                                                     │         │{"foo": "bar"} │                                        │capabilities: │
                                                                                     │     ┌───┴───────┬───────┘                                        └─┬────────────┴─┐
                                                                                     └────▶│Signature: │                                                  │{"id": "qwe"} │
                                                                                           └─┬─────────┴──────────────────────┐                     ┌─────┴────────┬─────┘
                                                                                             │BLS.agg(BLS.sign(Payload, sk2)) │───────┐             │capabilities: │
                                                                                             └────────────────────────────────┘       │             └─┬────────────┴──┐
                                                                                                                                      │               │{"foo": "bar"} │
                                                                                                                                      │         ┌─────┴──┬────────────┘
                                                                                                                                      │         │action: │
                                                                                                                                      │         └─┬──────┴─────────────────┐
                                                                                                                                      │           │save record {:id "qwe"} │
                                                                                                                                      │       ┌───┴───────┬────────────────┘
                                                                                                                                      └──────▶│Signature: │
                                                                                                                                              └─┬─────────┴──────────────────────┐
                                                                                                                                                │BLS.agg(BLS.sign(Payload, sk3)) │
                                                                                                                                                └────────────────────────────────┘
```
