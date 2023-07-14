<?php
namespace FTS\JwtRefreshService\Plugin;

use Magento\Framework\Exception\RuntimeException;
use Magento\Framework\Jwt\Claim\IssuedAt;
use Magento\Framework\Jwt\EncryptionSettingsInterface;
use Magento\Framework\Jwt\Jwe\Jwe;
use Magento\Framework\Jwt\Jwe\JweInterface;
use Magento\Framework\Jwt\Jws\Jws;
use Magento\Framework\Jwt\Jws\JwsInterface;
use Magento\Framework\Jwt\JwtInterface;
use Magento\Framework\Jwt\Payload\ClaimsPayload;
use Magento\Framework\Jwt\Payload\ClaimsPayloadInterface;
use Magento\JwtFrameworkAdapter\Model\JwtManager;

class IssuedAtDateOverride
{
    private IssuedAt $newIssuedAt;

    public function setNewIssuedAt(IssuedAt $issuedAt) : self
    {
        $this->newIssuedAt = $issuedAt;
        return $this;
    }

    /**
     * If we're in the middle of refreshing a JWT, we want to override the
     * incoming JWT parameters to have a different issued at date.
     *
     * @param JwtManager $subject
     * @param JwtInterface $jwt
     * @param EncryptionSettingsInterface $encryptionSettings
     * @return array
     * @throws RuntimeException Unknown type of JWT
     */
    public function beforeCreate(
        JwtManager $subject,
        JwtInterface $jwt,
        EncryptionSettingsInterface $encryptionSettings
    ): array {
        // Proceed as normal if no override has been set
        if (!isset($this->newIssuedAt)) {
            return [$jwt, $encryptionSettings];
        }
        if (!$jwt instanceof JwsInterface && !$jwt instanceof JweInterface) {
            throw new RuntimeException(__("Unable to override issue date claim of JWT - unhandled token type (JWS and JWE are supported)"));
        }
        // We need to rebuild $jwt but with updated claims. This code for making
        // a JwtInterface is taken from Magento\JwtUserToken\Model\Issuer.
        $claimsPayload = $jwt->getPayload();
        if (!$claimsPayload instanceof ClaimsPayloadInterface) {
            throw new RuntimeException(__("Unable to override issue date claim of JWT - JWT payload does not contain claims"));
        }
        // Override the auto-generated iat claim with the one provided
        $claims = $claimsPayload->getClaims();
        $claims['iat'] = $this->newIssuedAt;
        $newClaimsPayload = new ClaimsPayload($claims);
        // create a new JWT with the updated claims and continue with the build
        if ($jwt instanceof JwsInterface) {
            $newJwt = new Jws(
                $jwt->getProtectedHeaders(),
                $newClaimsPayload,
                $jwt->getUnprotectedHeaders()
            );
        } else {
            $newJwt = new Jwe(
                $jwt->getProtectedHeader(),
                $jwt->getSharedUnprotectedHeader(),
                $jwt->getPerRecipientUnprotectedHeaders(),
                $newClaimsPayload
            );
        }
        return [$newJwt, $encryptionSettings];
    }
}
