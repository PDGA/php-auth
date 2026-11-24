# pdga-auth

Auth related code for the PDGA's back-end PHP systems.

### Install Composer Deps

```
docker-compose run --rm -u $(id -u):$(id -g) composer install
```

### Run Unit Tests

```
./run-tests.sh
```

### Require this Library as a Dependency

```
composer require pdga/auth
```

## Signing Key Rotation

`TokenIssuer` accepts an optional list of additional verification keys:

```php
parent::__construct($issuer, $signing_key, [$other_key /* , ... */]);
```

Tokens are always signed with `$signing_key`. When decoding, the signature is
checked against `$signing_key` first, then each additional key in order.  This
allows keys to be rotated without invalidating existing tokens (e.g. logging out
active sessions).

To rotate from `OLD` to `NEW` across services that share tokens:

1. **Stage** - Deploy every service with signing key `OLD` and additional keys
   `[NEW]`. Nothing is signed with `NEW` yet, but every service accepts it.
2. **Flip** - Deploy every service with signing key `NEW` and additional keys
   `[OLD]`. New tokens are signed with `NEW`; existing tokens still verify.
3. **Retire** - Once the longest token duration has elapsed since the flip,
   deploy every service with signing key `NEW` and no additional keys.

The stage step is needed because deploys are not atomic.  Without it, a
service or instance that has flipped issues `NEW` tokens that a not-yet-updated
one (which only knows `OLD`) rejects.  It also keeps a rollback of the flip
safe, since the staged config still accepts `NEW`.

Note: version 2.x of this library requires HS256 keys of at least 32 bytes.
Rotate to a key of at least 32 bytes (and retire any shorter keys) before
upgrading to 2.x.
