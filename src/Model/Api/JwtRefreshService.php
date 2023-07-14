<?php
namespace FTS\JwtRefreshService\Model\Api;

use FTS\JwtRefreshService\Api\JwtRefreshServiceInterface;
use FTS\JwtRefreshService\Plugin\IssuedAtDateOverride;
use Magento\Authorization\Model\UserContextInterface;
use Magento\Framework\Exception\AuthorizationException;
use Magento\Framework\Exception\InvalidArgumentException;
use Magento\Framework\Jwt\Claim\IssuedAtFactory;
use Magento\Framework\Webapi\Request;
use Magento\Integration\Api\Data\UserToken;
use Magento\Integration\Api\Exception\UserTokenException;
use Magento\Integration\Api\UserTokenReaderInterface;
use Magento\Integration\Api\UserTokenValidatorInterface;
use Magento\Integration\Model\UserToken\UserTokenParametersFactory;
use Magento\JwtUserToken\Model\Data\JwtUserContext;
use Magento\JwtUserToken\Model\Issuer;

class JwtRefreshService implements JwtRefreshServiceInterface
{
    /**
     * @param ?string $token If provided, this token will be refreshed. Otherwise, the current request's bearer token will be used
     */
    public function __construct(
        private readonly UserTokenReaderInterface $userTokenReader,
        private readonly UserTokenValidatorInterface $userTokenValidator,
        private readonly Request $request,
        private readonly UserTokenParametersFactory $userTokenParametersFactory,
        private readonly IssuedAtFactory $issuedAtClaimFactory,
        private readonly Issuer $tokenIssuer,
        private readonly IssuedAtDateOverride $issuedAtDateOverride,
        private readonly ?string $token = null
    ) {}

    public function refreshAdminToken() : string
    {
        $token = $this->getUserToken();
        if (!$token->getUserContext() instanceof JwtUserContext) {
            throw new InvalidArgumentException(__("This endpoint can only be used to refresh JSON Web Tokens"));
        }

        // This may seem redundant since webapi.xml specifies that access to the 'Magento_Backend::admin' resource is
        // required - but it allows other modules to use the service class directly.
        if ($token->getUserContext()->getUserType() !== UserContextInterface::USER_TYPE_ADMIN) {
            throw new AuthorizationException(__("This endpoint can only be used to refresh admin user tokens"));
        }

        // We don't want the "issued at" time of the new token to change
        // compared to the original token, because the new token should be
        // affected by revocations based on the initial login time.
        //
        // Although the UserTokenParameters class takes an "issued" parameter,
        // we can't simply use that as it is always used to calculate the
        // expiry date (i.e. if we set it to the original issue time then the
        // token does not have its expiry time refreshed.)
        //
        // So, we use a plugin on the JWT manager class to rewrite the JWT
        // payload that it receives.
        $iat = $this->issuedAtClaimFactory->create([
            'value' => $token->getData()->getIssued(),
            'duplicate' => true
        ]);
        $this->issuedAtDateOverride->setNewIssuedAt($iat);

        // Issue a new token based on the existing context
        $userTokenParams = $this->userTokenParametersFactory->create();
        return $this->tokenIssuer->create($token->getUserContext(), $userTokenParams);
    }

    /**
     * @throws AuthorizationException
     */
    private function getUserToken() : UserToken
    {
        if ($this->token) {
            $token = $this->token;
        } else {
            $token = $this->getBearerTokenFromRequest();
        }
        try {
            $userToken = $this->userTokenReader->read($token);
            $this->userTokenValidator->validate($userToken);
            return $userToken;
        } catch (UserTokenException $e) {
            $this->bail();
        }
    }

    /**
     * @throws AuthorizationException
     */
    private function getBearerTokenFromRequest() : string
    {
        // This code is from Magento\Webapi\Model\Authorization\UserTokenContext
        // which we would ideally just use directly, but it does not expose the
        // parsed token to us, only the user ID and type.
        $authorizationHeaderValue = $this->request->getHeader('Authorization');
        if (!$authorizationHeaderValue) {
            $this->bail();
        }
        $headerPieces = explode(' ', $authorizationHeaderValue);
        if (count($headerPieces) !== 2 || strtolower($headerPieces[0]) !== 'bearer') {
            $this->bail();
        }
        return $headerPieces[1];
    }

    /**
     * @throws AuthorizationException
     */
    private function bail()
    {
        throw new AuthorizationException(__('Invalid bearer token'));
    }
}
