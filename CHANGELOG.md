## To be released

### Features :tada:

### Fixes :bug:

### Other

## 0.6.11

### Features

- Add a 2fa domain checker as part of the security center implementation

## 0.6.10

### Other

- Include custom AAGUID when generating passkeys.

## 0.6.9

### Fixes

- Versioning fixes.

## 0.6.8

### Other

- Configure Passkey authenticator display name.
- Expose new passkey fields to web.

## 0.6.7

### Other

- Add attestation_object to create passkey response for iOS.

## 0.6.6

### Features

- Add credential_id & user_handle to create passkey response.

## 0.6.5

### Features :tada:

- Prepare API to allow iOS to generate passkeys.

### Other

- Allow url without schema in passkey generation.

## 0.6.4

### Other

- Make passkey resolve challenge resilient to domain without protocol.

## 0.6.3

### Other

- Offer functions for parsing the passkey creation request.

## 0.6.2

### Other

- Expose more information when generating passkeys.

## 0.6.1

### Other

- Expose more information when generating passkeys.

## 0.6.0

### Features :tada:

- Initial passkey support.

## 0.5.6

### Fixes :bug:

- Fix TOTP generation.

## 0.5.5

### Other

- Relax restrictions when generating TOTP tokens.

## 0.5.4

### Other

- Add back `TotpUriParser`.

## 0.5.3

### Features

- Improve TOTP token generation to handle URIs and standalone secrets.

### Other

- Improved password scoring algorithm.

## 0.5.2

### Other

- Fixed password scoring algorithm.

## 0.5.1

### Other

- Renamed password scores.

## 0.5.0

### Features :tada:

- New password scoring algorithm.

## 0.4.0

### Features :tada:

- Credit card detector
- Better interfaces for web bindings

## 0.3.3

### Other

- Update of compilation settings of swift package to remove warnings

## 0.3.2

### Other

- Allow to generate TOTP token from secret

## 0.3.1

### Refactor

- Allow to pass time on TOTP token generation

## 0.3.0

### Features :tada:

- Allow to create signature bodies for NewUserInvites. 

## 0.2.2 (2023-10-11)

### Fixes :bug:

- Handle TOTP URI with empty secret

## 0.2.1 (2023-10-10)

### Fixes :bug:

- Android: Specify JNA as an AAR dependency explicitly.
- Handle empty edited TOTP URI

## 0.2.0 (2023-10-06)

### Features :tada:

- Password generation.

### Other

- Auto-publish.

## 0.1.0 (2023-10-03)

First version of the library.

### Features :tada:

- Alias prefix validation.
- TOTP parsing.
