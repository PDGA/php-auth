<?php

namespace PDGA\Auth\Test;

use PHPUnit\Framework\TestCase;
use PDGA\Exception\ForbiddenException;
use PDGA\Exception\UnauthorizedException;

final class TokenIssuerTest extends TestCase
{
    private $token_issuer;

    protected function setUp(): void
    {
        $this->token_issuer = new TestTokenIssuer();
    }

    /**
     * Basic check to see that a token is returned that matches the JWT format.
     */
    public function testIssueTokenFormat(): void
    {
        $token = $this->token_issuer->issueTokenFor('1', 60);

        $this->assertMatchesRegularExpression('/\w+\.\w+\.\w+/', $token);
    }

    /**
     * Check the token's claims.
     */
    public function testTokenClaims(): void
    {
        $token   = $this->token_issuer->issueTokenFor('1', 60);
        $payload = $this->token_issuer->decode($token);

        $this->assertSame('test-issuer', $payload['iss']);
        $this->assertSame($this->token_issuer->getAudience(), $payload['aud']);
        $this->assertSame('1', $payload['sub']);
        $this->assertSame(time(), $payload['iat'], 'Bad IAT', 1); // 1 second delta.
        $this->assertSame(time() + 60, $payload['exp'], 'Bad exp', 1); // 1 second delta.
    }

    /**
     * Signature manipulated.
     */
    public function testBadSig(): void
    {
        $token = $this->token_issuer->issueTokenFor('1', 60);

        // The signature is the third segment of the JWT.
        // Change the first character of the signature segment. Its bits are fully significant.
        // That is unlike the last character, whose low bits are padding.
        $parts = explode('.', $token);
        $signature = $parts[2];
        $signature[0] = $signature[0] === 'A' ? 'B' : 'A';
        $parts[2] = $signature;
        $token = implode('.', $parts);

        try {
            $payload = $this->token_issuer->decode($token);
            $this->fail('Expected ForbiddenException not thrown: ' . $token);
        } catch (ForbiddenException $ex) {
            $this->assertSame('Invalid signature.', $ex->getMessage());
        }
    }

    /**
     * Expired token.
     */
    public function testTokenExpired(): void
    {
        // Token valid for -1 seconds.
        $token = $this->token_issuer->issueTokenFor('1', -1);

        try {
            $payload = $this->token_issuer->decode($token);
            $this->assertTrue(false);
        } catch (UnauthorizedException $ex) {
            $this->assertSame('Token expired.', $ex->getMessage());
        }
    }

    /**
     * Invalid token.
     */
    public function testInvalidToken(): void
    {
        $token = 'asdf';

        try {
            $payload = $this->token_issuer->decode($token);
            $this->assertTrue(false);
        } catch (ForbiddenException $ex) {
            $this->assertSame('Invalid token.', $ex->getMessage());
        }
    }

    /**
     * Bad audience.
     */
    public function testBadAud(): void
    {
        // Mock out the verifyAudience method such that it returns false.
        $token_issuer = $this
            ->getMockBuilder(TestTokenIssuer::class)
            ->onlyMethods(['verifyAudience'])
            ->getMock();

        $token_issuer
            ->expects($this->once())
            ->method('verifyAudience')
            ->will($this->returnValue(false));

        $token = $token_issuer->issueTokenFor('1', 60);

        try {
            $payload = $token_issuer->decode($token);
            $this->assertTrue(false);
        } catch (ForbiddenException $ex) {
            $this->assertSame('Invalid audience.', $ex->getMessage());
        }
    }

    /**
     * Pulls the issuer.
     */
    public function testGetIssuer(): void
    {
        $this->assertSame('test-issuer', $this->token_issuer->getIssuer());
    }
}
