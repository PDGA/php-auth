<?php

namespace PDGA\Auth\Test;

use PDGA\Auth\TokenIssuer;

class TestTokenIssuer extends TokenIssuer
{
    public function __construct()
    {
        parent::__construct('test-issuer', '12345678901234567890123456789012');
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
