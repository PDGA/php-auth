<?php

namespace PDGA\Auth;

use PDGA\Exception\ForbiddenException;
use PDGA\Exception\UnauthorizedException;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;

abstract class TokenIssuer
{
    private $key;
    private $additional_verification_keys;
    private $issuer;

    /**
     * Initialize with an issuer (application name) and a signing key.
     *
     * @param string $issuer - Application name. Lands in the "iss" claim of issued tokens.
     * @param string $key - Signing key for tokens.  Used for generating signed
     * HMACs, and is the first key tried when verifying tokens.
     * @param array $additional_verification_keys - Optional list of extra keys
     * that are accepted when verifying tokens, but never used for signing.
     * Tokens signed with a previous (or upcoming) key remain valid while the rotation rolls out.
     */
    public function __construct(
        string $issuer,
        string $key,
        array $additional_verification_keys = []
    ) {
        $this->issuer = $issuer;
        $this->key = $key;
        $this->additional_verification_keys = $additional_verification_keys;
    }

    /**
     * Get the audience for the token.  This is application specific,
     * and PDGA micro-apps need to implement this.
     *
     * @return array An array of strings, where each is a
     * case-sensitive application name or URI.
     */
    abstract public function getAudience(): array;

    /**
     * Verify that a token's audience claim is valid.  This is called by
     * decode.
     *
     * @param array $audience A token's "aud" (audience) claim.
     *
     * @return bool true if the audience is authorized for the application.
     */
    abstract public function verifyAudience(array $audience): bool;

    /**
     * Expose the issuer, which is often one of the audiences in concrete
     * implementations.
     *
     * @return string The "iss" (issuer) claim on tokens.
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Issue a token for a subject (e.g. a user/device/service identifier).
     *
     * @param string $subject - A unique identifier for the subject.
     * Per the JWT spec, this should be a string or URI.
     * @param int $duration - the amout of time for which a token is
     * valid, in seconds.  This is added to the "iat" (issued at)
     * claim, and ends up in the "exp" (expires) claim.
     * @param array $additional_claims - An array of additional
     * claims to add to the token payload.
     *
     * @return string - A signed JSON web token, as a string.
     */
    public function issueTokenFor(
        string $subject,
        int $duration,
        array $additional_claims = []
    ): string
    {
        $now = time();

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->getAudience(),
            'sub' => $subject,
            'iat' => $now,
            'exp' => $now + $duration,
        ];

        $payload = array_merge($additional_claims, $payload);

        return JWT::encode($payload, $this->key, 'HS256');
    }

    /**
     * Decode (and verify) the token, then return its payload (claims) as an
     * array.  The signature is checked against the signing key first, then
     * against each additional verification key, in order.
     *
     * @param string $token - A JWT.
     *
     * @throws ForbiddenException if the token's signature does not match any
     * of the configured keys.
     * @throws ForbiddenException if the token's format is invalid (not a JWT).
     * @throws ForbiddenException if the token's audience does not contain the
     * audience returned from the abstract getAudience method.
     * @throws UnauthorizedException if the token is expired.
     *
     * @return array The token's payload.
     */
    public function decode(
        string $token
    ): array
    {
        $payload = null;
        $keys = array_merge([$this->key], $this->additional_verification_keys);

        // Decode the token, which checks the signature and that it has not expired.
        // Order is important here. The signature is checked before the expiration.
        // A token must be successfully decoded before the expiration can be checked.
        foreach ($keys as $key)
        {
            try
            {
                $payload = (array)JWT::decode($token, new Key($key, 'HS256'));
                break;
            }
            catch (SignatureInvalidException $e)
            {
                continue;
            }
            catch (ExpiredException $e)
            {
                throw new UnauthorizedException('Token expired.');
            }
            catch (\UnexpectedValueException $e)
            {
                throw new ForbiddenException('Invalid token.');
            }
        }

        // The token could not be decoded.
        if ($payload === null)
        {
            throw new ForbiddenException('Invalid signature.');
        }

        // Make sure that the audience is valid for use with the concrete application.
        if (!$this->verifyAudience($payload['aud']))
        {
            throw new ForbiddenException('Invalid audience.');
        }

        return $payload;
    }
}
