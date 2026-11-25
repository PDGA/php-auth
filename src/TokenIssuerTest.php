<?php
use PHPUnit\Framework\TestCase;

use PDGA\Exception\ForbiddenException;
use PDGA\Exception\UnauthorizedException;

use PDGA\Auth\TokenIssuer;

class TestTokenIssuer extends TokenIssuer {
    public function __construct(
        string $key = 'test-key',
        array $additional_verification_keys = []
    )
    {
        parent::__construct('test-issuer', $key, $additional_verification_keys);
    }

    public function getAudience(): array
    {
        return ['test-aud'];
    }

    public function verifyAudience(array $audience): bool
    {
        return in_array($this->getAudience()[0], $audience);
    }
}

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
        $token = $this->token_issuer->issueTokenFor('1', 60);
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
    public function testBadSignature(): void
    {
        $token = $this->token_issuer->issueTokenFor('1', 60);
        // Changes the last character of the token to an A (the sig is the last
        // part of the JWT).
        $token = substr_replace($token, 'A', strlen($token) - 1);

        try
        {
            $payload = $this->token_issuer->decode($token);
            $this->assertTrue(false);
        }
        catch (ForbiddenException $ex)
        {
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

        try
        {
            $payload = $this->token_issuer->decode($token);
            $this->assertTrue(false);
        }
        catch (UnauthorizedException $ex)
        {
            $this->assertSame('Token expired.', $ex->getMessage());
        }
    }

    /**
     * Invalid token.
     */
    public function testInvalidToken(): void
    {
        $token = 'asdf';

        try
        {
            $payload = $this->token_issuer->decode($token);
            $this->assertTrue(false);
        }
        catch (ForbiddenException $ex)
        {
            $this->assertSame('Invalid token.', $ex->getMessage());
        }
    }

    /**
     * Bad audience.
     */
    public function testBadAudience(): void
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

        try
        {
            $payload = $token_issuer->decode($token);
            $this->assertTrue(false);
        }
        catch (ForbiddenException $ex)
        {
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

    /**
     * A token signed with an old key is accepted when the old key is configured as an
     * additional verification key, including when it is not the first additional key.
     */
    public function testDecodeWithAdditionalVerificationKey(): void
    {
        $old_issuer = new TestTokenIssuer('old-key');
        $new_issuer = new TestTokenIssuer('new-key', ['other-key', 'old-key']);

        $token = $old_issuer->issueTokenFor('1', 60);
        $payload = $new_issuer->decode($token);

        $this->assertSame('1', $payload['sub']);
    }

    /**
     * Tokens are signed with the primary key, never an additional key.
     */
    public function testIssueSignsWithPrimaryKey(): void
    {
        $issuer = new TestTokenIssuer('new-key', ['old-key']);
        $token = $issuer->issueTokenFor('1', 60);

        $primary_only = new TestTokenIssuer('new-key');
        $this->assertSame('1', $primary_only->decode($token)['sub']);
    }

    /**
     * An expired token signed with an additional verification key is reported as expired (Unauthorized).
     */
    public function testExpiredTokenWithAdditionalVerificationKey(): void
    {
        $old_issuer = new TestTokenIssuer('old-key');
        $new_issuer = new TestTokenIssuer('new-key', ['old-key']);

        // Token valid for -1 seconds.
        $token = $old_issuer->issueTokenFor('1', -1);

        try
        {
            $new_issuer->decode($token);
            $this->fail('Expected UnauthorizedException not thrown.');
        }
        catch (UnauthorizedException $ex)
        {
            $this->assertSame('Token expired.', $ex->getMessage());
        }
    }

    /**
     * An expired token signed with an unknown key is reported as a bad signature, not as expired.
     */
    public function testExpiredTokenWithUnknownKey(): void
    {
        $unknown_issuer = new TestTokenIssuer('unknown-key');
        $issuer = new TestTokenIssuer('new-key', ['old-key']);

        // Token valid for -1 seconds.
        $token = $unknown_issuer->issueTokenFor('1', -1);

        try
        {
            $issuer->decode($token);
            $this->fail('Expected ForbiddenException not thrown.');
        }
        catch (ForbiddenException $ex)
        {
            $this->assertSame('Invalid signature.', $ex->getMessage());
        }
    }
}
