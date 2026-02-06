---
title: "Simple PKCS #11 Remote Procedure Call (RPC) Protocol"
abbrev: "PKCS #11 RPC"
category: info

docname: draft-ueno-pkcs11-rpc-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: SEC
# workgroup: Network Working Group
keyword:
 - PKCS #11
 - cryptoki
 - RPC
 - HSM

author:
 -
    fullname: Daiki Ueno
    organization: Red Hat, Inc.
    email: dueno@redhat.com
 -
    fullname: Zoltán Fridrich
    organization: Red Hat, Inc.
    email: zfridric@redhat.com

normative:
  PKCS11-v2.40:
    title: "PKCS #11 Cryptographic Token Interface Base Specification Version 2.40"
    target: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
    author:
      org: OASIS
    date: 2015-04

  PKCS11-v3.1:
    title: "PKCS #11 Cryptographic Token Interface Specification Version 3.1"
    target: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.pdf
    author:
      org: OASIS
    date: 2021-06

  RFC5234:

informative:
  KMIP:
    title: "Key Management Interoperability Protocol Specification Version 2.1"
    target: https://docs.oasis-open.org/kmip/kmip-spec/v2.1/kmip-spec-v2.1.html
    author:
      org: OASIS
    date: 2020-01

  DBUS:
    title: "D-Bus Specification"
    target: https://dbus.freedesktop.org/doc/dbus-specification.html
    author:
      org: freedesktop.org

  P11-GLUE:
    title: "p11-glue: Standardizing PKCS #11"
    target: https://p11-glue.github.io/p11-glue/
    author:
      org: p11-glue Project

...

--- abstract

This document specifies the PKCS #11 RPC (Remote Procedure Call) protocol, which enables remote access to PKCS #11 cryptographic modules. The protocol is designed for local communication scenarios such as forwarding PKCS #11 modules into sandboxed environments and enabling inter-process communication between applications and cryptographic service providers. Unlike general-purpose key management protocols such as KMIP, the PKCS #11 RPC protocol prioritizes minimal overhead and faithful representation of PKCS #11 semantics.

--- middle

# Introduction

PKCS #11 {{PKCS11-v2.40}} {{PKCS11-v3.1}} defines a platform-independent API (Cryptoki) for cryptographic tokens. Traditionally, PKCS #11 modules are loaded as shared libraries (via `dlopen` on Unix or `LoadLibrary` on Windows) within the same process address space as the calling application. However, several use cases require remote access to PKCS #11 functionality:

- Sandboxing proprietary PKCS #11 modules using bubblewrap or similar isolation tools
- Delegating cryptographic operations from inside enclaves to host systems
- Forwarding system trust stores into sandboxes

The PKCS #11 RPC protocol addresses these use cases by providing a wire protocol that faithfully represents PKCS #11 function calls and their semantics.

## Relationship to Other Protocols

While KMIP {{KMIP}} provides a comprehensive protocol for key management operations, the PKCS #11 RPC protocol serves a different purpose:

- **Scope**: PKCS #11 RPC is specifically designed for exposing existing PKCS #11 modules over a trusted communication channel, whereas KMIP is a general-purpose key management protocol
- **Design Goals**: PKCS #11 RPC prioritizes minimal overhead and faithful PKCS #11 semantics, making it suitable for local IPC scenarios
- **Use Cases**: PKCS #11 RPC is optimized for scenarios like sandbox forwarding, where existing PKCS #11 modules need to be accessed remotely without translation

The protocol does not aim to be a general-purpose key management protocol or to provide features beyond what PKCS #11 itself offers.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol Overview

The PKCS #11 RPC protocol is a simple request-response protocol that serializes PKCS #11 function calls and their arguments into binary messages transmitted over a bidirectional byte stream (typically stdin/stdout, Unix domain sockets, or VSOCK sockets).

## Architecture

The protocol consists of:

1. **Transport Layer**: Provides a reliable bidirectional byte stream
2. **Message Layer**: Defines message framing and serialization
3. **Call Layer**: Maps PKCS #11 functions to RPC calls
4. **Version Negotiation**: Allows clients and servers to agree on protocol capabilities

~~~
┌─────────────────────────────────────────────┐
│          PKCS #11 Application               │
└─────────────────┬───────────────────────────┘
                  │ PKCS #11 API
┌─────────────────▼───────────────────────────┐
│          PKCS #11 RPC Client                │
└─────────────────┬───────────────────────────┘
                  │ RPC Protocol
                  │ (over transport)
┌─────────────────▼───────────────────────────┐
│          PKCS #11 RPC Server                │
└─────────────────┬───────────────────────────┘
                  │ PKCS #11 API
┌─────────────────▼───────────────────────────┐
│     PKCS #11 Module (e.g., SoftHSM)         │
└─────────────────────────────────────────────┘
~~~

# Transport Layer

The protocol operates over a reliable, ordered, bidirectional byte stream. This document defines three transport mechanisms: pipe, Unix domain socket, and VSOCK. A transport can be identified by a transport address, which consists of a transport type and transport attributes.

## Transport Address

Formally, a transport address takes the following form (for explanation of Augmented BNF, see {{RFC5234}}).

~~~
pk11-transport-addr   = pk11-transport-type ":" pk11-transport-attrs
pk11-transport-attrs  = [ pk11-transport-attr *(";" pk11-transport-attr) ]
pk11-attr-name-char   = ALPHA / DIGIT / "-" / "_"
pk11-attr-value-char  = %x20-3A / %x3C-7E /
pk11-attr-value-qchar = pk11-attr-value-char / ("\" %x20-%7E)
pk11-attr-value       = *pk11-attr-value-char /
                        DQUOTE *pk11-attr-value-qchar DQUOTE
						     ; quoted strings may contain backslash escaped
							 ; characters, such as \;, \"
pk11-transport-attr   = 1*pk11-attr-name-char "=" *pk11-attr-value
~~~

In the p11-glue project {{P11-GLUE}}, this is configured in module configuration files with the `remote:` keyword.

## Transport Types

### Pipe Transport

The client launches a server executable and communicates via stdin/stdout pipes. The transport type of the pipe transport is "exec", which MUST take a transport attribute "command" to specify the command line of the server executable.

### Unix Domain Socket Transport

The client connects to a server listening on a Unix domain socket. The transport type of the Unix domain socket transport is "unix", which MUST take a transport attribute "path" to specify the socket path on the filesystem.

### VSOCK Transport

For virtual machine scenarios, the protocol can operate over VSOCK sockets. The transport type of the VSOCK transport is "vsock", which must take two transport attributes, "cid" to specify the Content Identifier (CID) and "port" to specify the port number.

## Transport Address Examples

This section contains some example of how transport can be identified using the transport address.

The p11-glue project {{P11-GLUE}} provides a simple helper program, `p11-kit remote`, which translates PKCS #11 RPC into C function calls.

The following example instructs the client to launch the `p11-kit remote` command and connect to it through a pipe transport.

~~~
exec:command="p11-kit remote /usr/lib64/pkcs11/libpkcs11module.so"
~~~

This is useful to sandbox a proprietary PKCS #11 modules. The command line of the above can be inside a sandbox created with bubblewrap.

~~~
exec:command="bwrap --unshare-all --dir /tmp --ro-bind /etc/conf /etc/conf --proc /proc --dev /dev --ro-bind /usr /usr --symlink /usr/lib64 /lib64 --ro-bind /run/pcscd /run/pcscd p11-kit remote /usr/lib64/pkcs11/libpkcs11module.so"
~~~

The p11-glue project {{P11-GLUE}} also provides a standalone server program, `p11-kit server`, which listens on a Unix domain socket. The following example tells the client to connect to a Unix domain socket on the path "/path/to/socket".

~~~
unix:path=/path/to/socket
~~~

Similarly, if the server is running on a host of a virtual machine, the client can connect to it with the following address, where CID 2 is the well-known address of the host.

~~~
vsock:cid=2;port=1111
~~~

# Version Negotiation

The protocol supports version negotiation to enable backward compatibility and feature evolution. The negotiation occurs immediately after transport establishment and before any PKCS #11 operations.

## Protocol Versions

The following protocol versions are defined:

- **Version 0**: Initial version supporting PKCS #11 2.x functions
- **Version 1**: Adds PKCS #11 3.0 functions (message-based encryption, C_LoginUser, C_SessionCancel)
- **Version 2**: Adds functions with mechanism parameter updates (C_InitToken2, C_DeriveKey2)

## Negotiation Procedure

The version negotiation follows a challenge-and-reconnect approach for transports that support reconnection:

1. Client sends a single byte containing its maximum supported version
2. Server receives the client version byte
3. Server determines the negotiated version:
   - If client version > server maximum: use server maximum
   - Otherwise: use client version
4. Server sends a single byte containing the negotiated version
5. Client receives negotiated version byte

If the server does not support version negotiation (i.e., only supports version 0), it will not respond correctly to non-zero version bytes. In this case:

1. Client detects negotiation failure
2. Client disconnects from server
3. Client reconnects to server
4. Client sends version byte 0
5. Server acknowledges with version byte 0

### Example: Successful Negotiation

~~~
Client                           Server
   |                                |
   |------- Version 2 (0x02) ------>|
   |                                | (Server max = 2)
   |<------ Version 2 (0x02) -------|
   |                                |
~~~

### Example: Downgrade to Version 1

~~~
Client                           Server
   |                                |
   |------- Version 2 (0x02) ------>|
   |                                | (Server max = 1)
   |<------ Version 1 (0x01) -------|
   |                                |
   |---- Reconnect ---------------->|
   |                                |
   |------- Version 1 (0x01) ------>|
   |<------ Version 1 (0x01) -------|
   |                                |
~~~

### Example: Fallback for Legacy Server

~~~
Client                           Server (v0 only)
   |                                |
   |------- Version 2 (0x02) ------>|
   |                                | (No response or error)
   | <-- (Connection Error) --------|
   |                                |
   |---- Reconnect ---------------->|
   |                                |
   |------- Version 0 (0x00) ------>|
   |<------ Version 0 (0x00) -------|
   |                                |
~~~

# Message Format

All RPC messages follow a consistent framing format consisting of a header, optional options area, and message body.

## Message Header

Each message begins with a 12-byte header:

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Call Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Options Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Buffer Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Where:

- **Call Code** (4 bytes): Unsigned 32-bit integer identifying the function call or response. For requests, this identifies the PKCS #11 function. For responses, this echoes the call code from the request.
- **Options Length** (4 bytes): Length in bytes of the options area
- **Buffer Length** (4 bytes): Length in bytes of the message body

All multi-byte integers are encoded in network byte order (big-endian).

## Options Area

The options area contains transport-specific metadata. In the current implementation, it typically contains the module name for multi-module scenarios. The format of the options area is implementation-defined.

## Message Body

The message body contains the serialized function arguments (for requests) or return values (for responses).

### Request Message Body

Request messages consist of:

1. Call ID (4 bytes): Identifies the PKCS #11 function
2. Signature (variable): Null-terminated signature string
3. Arguments (variable): Serialized function arguments according to the signature

### Response Message Body

Response messages consist of:

1. Call ID (4 bytes): Echo of the request call ID
2. Signature (variable): Null-terminated signature string
3. Return values (variable): Serialized return values according to the signature

## Call Codes

Call codes are monotonically increasing integers assigned by the client for request-response matching. The server MUST echo the call code in the response.

# Serialization Format

The protocol uses a type-signature based serialization format inspired by the D-Bus message format {{DBUS}}. Each PKCS #11 function has associated request and response signatures that define the types and order of arguments.

## Type Signatures

Type signatures comprises a series of type codes as defined below. Most of them represent a single type, such as CK_BYTE, while a couple of them, `a` and `f`, represent arrays and output buffers of elements in other types signified by the following type code. For example, `ay` means an array of CK_BYTE.

| Code | Meaning                                    |
|------|--------------------------------------------|
| `a_` | Prefix denoting array of type `_`         |
| `A`  | CK_ATTRIBUTE                               |
| `f_` | Prefix denoting buffer for type `_`       |
| `M`  | CK_MECHANISM                               |
| `P`  | Mechanism parameter (updated)              |
| `u`  | CK_ULONG                                   |
| `s`  | Space-padded string                        |
| `v`  | CK_VERSION                                 |
| `y`  | CK_BYTE                                    |
| `z`  | Null-terminated string                     |

## Primitive Types

### CK_BYTE (type 'y')

Serialized as a single byte.

### CK_ULONG (type 'u')

Serialized as a 64-bit unsigned integer in network byte order.

## String Types

### NUL-terminated String (type 'z')

Serialized as:

1. Length (4 bytes): Number of bytes including NUL (0x0) terminator
2. Bytes (variable): UTF-8 encoded string with NUL (0x0) terminator

### Space-padded String (type 's')

Used for fixed-length PKCS #11 string fields (e.g., CK_TOKEN_INFO labels). Serialized as:

1. Length (4 bytes): Total length of the string field
2. Bytes (variable): UTF-8 encoded string, space-padded to length

## Record Types

### CK_VERSION (type 'v')

Serialized as two bytes: major version followed by minor version.

### CK_MECHANISM (type 'M')

Serialized as:
1. Mechanism type (4 bytes): CK_MECHANISM_TYPE value
2. Parameter type (1 byte): Type code for the parameter
3. Parameter length (4 bytes): Length of parameter data
4. Parameter data (variable): Mechanism-specific parameter

The parameter type and format depend on the mechanism. Common mechanisms have specific serialization rules:

- CKM_RSA_PKCS_PSS: Serialized as CK_RSA_PKCS_PSS_PARAMS
- CKM_RSA_PKCS_OAEP: Serialized as CK_RSA_PKCS_OAEP_PARAMS
- CKM_AES_GCM: Serialized as CK_GCM_PARAMS
- CKM_ECDH1_DERIVE: Serialized as CK_ECDH1_DERIVE_PARAMS

### CK_ATTRIBUTE (type 'A')

Attributes require special handling due to their recursive nature (attributes can contain attribute arrays).

Serialized as:
1. Attribute type (4 bytes): CK_ATTRIBUTE_TYPE value
2. Value length (4 bytes): Length of pValue
3. Value data (variable): Depends on attribute type

Note that if the CKF_ARRAY_ATTRIBUTE flag is set in the attribute type, the value data is recursively serialized, in a depth-first, pre-order traversal.

## Array Types

Arrays are serialized as:

1. Length (4 bytes): Number of elements following
2. Data (variable): Array contents

The size of each element is determined by the following type signature. For example, a CK_BYTE array ('ay') has elements of one octet, while a CK_ULONG array ('au') has elements of 8 octets.

## Buffer Types

The protocol implements the PKCS #11 convention for variable-length output parameters, signified by the `f_` (buffer) type signature.

The serialization of the argument of type `f_` depends on the element type. For the types with known sizes, the client only sends the number of elements. For the types with unknown sizes, the client additionally sends "templates" with which only the fixed fields are filled.

For example, to receive an attribute array with C_GetAttributeValue, the client sends a request with a type signature including `fA` and the corresponding argument serialized as:

1. Length (4 bytes): Number of elements following
2. Templates: Array of CK_ATTRIBUTE serialized as if pValue field is NULL

Note that for recursively serialized attributes, only the leaf CK_ATTRIBUTE values have pValue field set to NULL.

When the call is successfull, the server responds with an array of CK_ATTRIBUTE `aA` filled with the actual ulValueLen and pValue for each attribute.

# Function Call Mappings

Each PKCS #11 function is mapped to an RPC call with a unique call identifier and type signature.

## Call Identifiers

Call identifiers are defined in the range:

- 0: P11_RPC_CALL_ERROR (error response)
- 1-57: PKCS #11 2.x functions
- 58-79: PKCS #11 3.0 functions (version 1+)
- 80-81: Extended functions with mechanism parameter updates (version 2+)

## Example Function Mappings

### C_GetMechanismList

Request signature: `"ufu"` (slot_id, buffer_for_mechanisms, count)
Response signature: `"au"` (array_of_mechanisms)

~~~
Request:
  - CK_SLOT_ID slot_id (u)
  - Buffer indicator for mechanisms (f)
  - CK_ULONG count (u) - capacity of buffer

Response:
  - CK_MECHANISM_TYPE array (au)
~~~

### C_GetAttributeValue

Request signature: `"uufA"` (session, object, buffer_for_attributes)
Response signature: `"aAu"` (attributes_array, result_code)

~~~
Request:
  - CK_SESSION_HANDLE session (u)
  - CK_OBJECT_HANDLE object (u)
  - Attribute template (fA)

Response:
  - Filled attribute array (aA)
  - CK_RV result code (u)
~~~

### C_Encrypt

Request signature: `"uayfy"` (session, plaintext_data, buffer_for_ciphertext)
Response signature: `"ay"` (ciphertext_data)

~~~
Request:
  - CK_SESSION_HANDLE session (u)
  - Plaintext data (ay)
  - Buffer for ciphertext (fy)

Response:
  - Ciphertext data (ay)
~~~

## PKCS #11 3.0 Functions (Version 1+)

Version 1 of the protocol adds support for PKCS #11 3.0 functions:

- C_LoginUser (call ID 58): Enhanced login with username
- C_SessionCancel (call ID 59): Cancel ongoing session operations
- Message-based encryption functions (call IDs 60-67):
  - C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal
  - C_MessageDecryptInit, C_DecryptMessage, C_DecryptMessageBegin, C_DecryptMessageNext, C_MessageDecryptFinal
- Message-based signature functions (call IDs 68-75):
  - C_MessageSignInit, C_SignMessage, C_SignMessageBegin, C_SignMessageNext, C_MessageSignFinal
  - C_MessageVerifyInit, C_VerifyMessage, C_VerifyMessageBegin, C_VerifyMessageNext, C_MessageVerifyFinal

## Extended Functions (Version 2+)

Version 2 adds functions that return updated mechanism parameters:

### C_InitToken2 (call ID 80)

Request signature: `"uays"` (slot_id, pin, label)
Response signature: `""`

Enhanced version of C_InitToken using space-padded string for label instead of null-terminated.

### C_DeriveKey2 (call ID 81)

Request signature: `"uMuaA"` (session, mechanism, base_key, template)
Response signature: `"uPu"` (derived_key_handle, updated_mechanism_params, result_code)

Enhanced version of C_DeriveKey that returns updated mechanism parameters. This is particularly useful for mechanisms like Kyber KEM where the encapsulation produces a ciphertext that must be returned to the caller.

The `P` type (mechanism parameter update) serializes the updated pParameter field of the CK_MECHANISM structure according to the mechanism type.

# Protocol Version Differences

This section summarizes the functional differences between protocol versions.

## Version 0

Initial protocol version supporting PKCS #11 2.40 functions:

- All functions from C_Initialize through C_WaitForSlotEvent
- Call IDs 1-57
- No version negotiation (always uses version byte 0x00)

## Version 1

Adds PKCS #11 3.0 function support:

- Version negotiation support
- C_LoginUser and C_SessionCancel
- Message-based encryption functions
- Message-based signature functions
- Call IDs 58-79

Backward compatibility: Version 1 servers can communicate with version 0 clients by using only version 0 function calls.

## Version 2

Adds functions with mechanism parameter updates:

- C_InitToken2: Uses space-padded label string
- C_DeriveKey2: Returns updated mechanism parameters
- Call IDs 80-81

Backward compatibility:
- Version 2 servers can downgrade to version 1 or 0
- For version 0-1 clients, C_InitToken and C_DeriveKey are used
- Mechanism parameter updates are not available at lower versions

# Error Handling

## PKCS #11 Return Codes

All PKCS #11 return codes (CK_RV) are transmitted as unsigned 32-bit integers in response messages. The protocol does not define additional error codes beyond those in PKCS #11.

## Protocol Errors

Protocol-level errors are handled as follows:

### Parse Errors

If the server cannot parse a request message:
1. Server sends P11_RPC_CALL_ERROR response
2. Response contains only CKR_GENERAL_ERROR return code
3. Connection may be closed

### Version Negotiation Failure

If version negotiation fails:
1. Client detects authentication error
2. Client disconnects
3. Client attempts reconnection with version 0
4. If reconnection fails, client returns CKR_DEVICE_ERROR

### Transport Errors

If the transport layer fails:
1. Pending operations return CKR_DEVICE_ERROR
2. Connection is closed
3. Subsequent operations return CKR_DEVICE_REMOVED

# Security Considerations

## Authentication

The protocol itself does not provide authentication mechanisms. Authentication is delegated to the transport layer:

- For Unix domain sockets: File system permissions and optional SO_PEERCRED
- For VSOCK: VM isolation boundaries

## Confidentiality and Integrity

The protocol does not provide encryption or integrity protection. These properties must be provided by:

- Operating system isolation (e.g., Unix domain sockets with file system permissions)
- Hypervisor isolation (e.g., VSOCK between VMs)

For scenarios requiring confidentiality and integrity without transport-level security, implementers should use TLS or similar protocols.

## Sandboxing

A key use case for the protocol is to sandbox untrusted PKCS #11 modules. When sandboxing:

- The server process should run with minimal privileges
- File system access should be restricted using tools like bubblewrap
- Seccomp filters should limit available system calls
- Resource limits should prevent denial of service

## Sensitive Data

The protocol transmits sensitive cryptographic material (keys, PINs, plaintext) in serialized form. Implementations must:

- Ensure transport channels are appropriately secured
- Zero sensitive memory after use
- Avoid logging sensitive parameters
- Respect PKCS #11 CKA_SENSITIVE and CKA_EXTRACTABLE attributes

## Input Validation

Servers must validate all input parameters:

- Array lengths must be checked against buffer sizes
- Attribute types must be validated
- Mechanism parameters must be validated according to PKCS #11 specifications
- Call IDs must be within valid ranges

Failure to validate inputs may lead to buffer overflows, denial of service, or information disclosure.

# IANA Considerations

This document has no IANA actions.

The protocol uses private handshake identifiers and does not require registry allocations. Future extensions may define additional type codes or call identifiers, which should be coordinated through the p11-kit project.

# Implementation Considerations

## Endianness and Data Models

The protocol uses network byte order (big-endian) for all multi-byte integers. The 64-bit encoding of CK_ULONG ensures interoperability across different platforms:

- LP64 systems (Unix/Linux 64-bit): CK_ULONG is 64-bit natively
- LLP64 systems (Windows 64-bit): CK_ULONG is 32-bit natively
- ILP32 systems (32-bit): CK_ULONG is 32-bit natively

Implementations must handle this conversion carefully, particularly when CK_ULONG values exceed 32-bit range on LLP64 systems.

## Buffer Management

The protocol's variable-length output convention requires two round trips for unknown-size outputs:

1. First call with NULL pointer to determine size
2. Second call with appropriately sized buffer

Implementations should optimize common cases where sizes are known or bounded.

## Mechanism Parameter Handling

Different PKCS #11 mechanisms use different parameter structures. Implementations must:

- Maintain tables mapping mechanism types to parameter structures
- Validate parameter structures according to PKCS #11 specifications
- Handle vendor-specific mechanisms gracefully

## Threading and Concurrency

The protocol supports concurrent calls through the call code mechanism. Multiple threads can:

- Send requests with different call codes
- Receive responses in any order
- Match responses to requests via call code

Implementations must ensure thread-safe access to the transport layer and proper request-response matching.

## Performance Optimization

For high-performance scenarios:

- Connection pooling can reduce setup overhead
- Batch operations should be used when available
- Local caching of token information can reduce round trips
- Unix domain sockets typically offer better performance than exec-based transports

--- back

# Acknowledgments
{:numbered="false"}

The author would like to thank Stef Walter for creating the p11-kit project and designing the initial RPC protocol. Thanks also to the p11-glue community for their work on standardizing PKCS #11 practices.

# Complete Function Signature Table
{:numbered="false"}

This appendix provides a complete reference of all PKCS #11 function signatures in the protocol.

| Call ID | Function Name              | Request Signature | Response Signature |
|---------|----------------------------|-------------------|--------------------|
| 0       | ERROR                      | N/A               | u                  |
| 1       | C_Initialize               | ayyay             |                    |
| 2       | C_Finalize                 |                   |                    |
| 3       | C_GetInfo                  |                   | vsusv              |
| 4       | C_GetSlotList              | yfu               | au                 |
| 5       | C_GetSlotInfo              | u                 | ssuvv              |
| 6       | C_GetTokenInfo             | u                 | ssssuuuuuuuuuuuvvs |
| 7       | C_GetMechanismList         | ufu               | au                 |
| 8       | C_GetMechanismInfo         | uu                | uuu                |
| 9       | C_InitToken                | uayz              |                    |
| 10      | C_OpenSession              | uu                | u                  |
| 11      | C_CloseSession             | u                 |                    |
| 12      | C_CloseAllSessions         | u                 |                    |
| 13      | C_GetSessionInfo           | u                 | uuuu               |
| 14      | C_InitPIN                  | uay               |                    |
| 15      | C_SetPIN                   | uayay             |                    |
| 16      | C_GetOperationState        | ufy               | ay                 |
| 17      | C_SetOperationState        | uayuu             |                    |
| 18      | C_Login                    | uuay              |                    |
| 19      | C_Logout                   | u                 |                    |
| 20      | C_CreateObject             | uaA               | u                  |
| 21      | C_CopyObject               | uuaA              | u                  |
| 22      | C_DestroyObject            | uu                |                    |
| 23      | C_GetObjectSize            | uu                | u                  |
| 24      | C_GetAttributeValue        | uufA              | aAu                |
| 25      | C_SetAttributeValue        | uuaA              |                    |
| 26      | C_FindObjectsInit          | uaA               |                    |
| 27      | C_FindObjects              | ufu               | au                 |
| 28      | C_FindObjectsFinal         | u                 |                    |
| 29      | C_EncryptInit              | uMu               |                    |
| 30      | C_Encrypt                  | uayfy             | ay                 |
| 31      | C_EncryptUpdate            | uayfy             | ay                 |
| 32      | C_EncryptFinal             | ufy               | ay                 |
| 33      | C_DecryptInit              | uMu               |                    |
| 34      | C_Decrypt                  | uayfy             | ay                 |
| 35      | C_DecryptUpdate            | uayfy             | ay                 |
| 36      | C_DecryptFinal             | ufy               | ay                 |
| 37      | C_DigestInit               | uM                |                    |
| 38      | C_Digest                   | uayfy             | ay                 |
| 39      | C_DigestUpdate             | uay               |                    |
| 40      | C_DigestKey                | uu                |                    |
| 41      | C_DigestFinal              | ufy               | ay                 |
| 42      | C_SignInit                 | uMu               |                    |
| 43      | C_Sign                     | uayfy             | ay                 |
| 44      | C_SignUpdate               | uay               |                    |
| 45      | C_SignFinal                | ufy               | ay                 |
| 46      | C_SignRecoverInit          | uMu               |                    |
| 47      | C_SignRecover              | uayfy             | ay                 |
| 48      | C_VerifyInit               | uMu               |                    |
| 49      | C_Verify                   | uayay             |                    |
| 50      | C_VerifyUpdate             | uay               |                    |
| 51      | C_VerifyFinal              | uay               |                    |
| 52      | C_VerifyRecoverInit        | uMu               |                    |
| 53      | C_VerifyRecover            | uayfy             | ay                 |
| 54      | C_DigestEncryptUpdate      | uayfy             | ay                 |
| 55      | C_DecryptDigestUpdate      | uayfy             | ay                 |
| 56      | C_SignEncryptUpdate        | uayfy             | ay                 |
| 57      | C_DecryptVerifyUpdate      | uayfy             | ay                 |
| 58      | C_GenerateKey              | uMaA              | u                  |
| 59      | C_GenerateKeyPair          | uMaAaA            | uu                 |
| 60      | C_WrapKey                  | uMuufy            | ay                 |
| 61      | C_UnwrapKey                | uMuayaA           | u                  |
| 62      | C_DeriveKey                | uMuaA             | u                  |
| 63      | C_SeedRandom               | uay               |                    |
| 64      | C_GenerateRandom           | ufy               | ay                 |
| 65      | C_WaitForSlotEvent         | u                 | u                  |
| 66      | C_LoginUser                | uuayay            |                    |
| 67      | C_SessionCancel            | uu                |                    |
| 68      | C_MessageEncryptInit       | uMu               |                    |
| 69      | C_EncryptMessage           | uayayayfy         | ay                 |
| 70      | C_EncryptMessageBegin      | uayay             |                    |
| 71      | C_EncryptMessageNext       | uayayfyu          | ay                 |
| 72      | C_MessageEncryptFinal      | u                 |                    |
| 73      | C_MessageDecryptInit       | uMu               |                    |
| 74      | C_DecryptMessage           | uayayayfy         | ay                 |
| 75      | C_DecryptMessageBegin      | uayay             |                    |
| 76      | C_DecryptMessageNext       | uayayfyu          | ay                 |
| 77      | C_MessageDecryptFinal      | u                 |                    |
| 78      | C_MessageSignInit          | uMu               |                    |
| 79      | C_SignMessage              | uayayfy           | ay                 |
| 80      | C_SignMessageBegin         | uay               |                    |
| 81      | C_SignMessageNext          | uayayyfy          | ay                 |
| 82      | C_MessageSignFinal         | u                 |                    |
| 83      | C_MessageVerifyInit        | uMu               |                    |
| 84      | C_VerifyMessage            | uayayay           |                    |
| 85      | C_VerifyMessageBegin       | uay               |                    |
| 86      | C_VerifyMessageNext        | uayayay           |                    |
| 87      | C_MessageVerifyFinal       | u                 |                    |
| 88      | C_InitToken2               | uays              |                    |
| 89      | C_DeriveKey2               | uMuaA             | uPu                |
