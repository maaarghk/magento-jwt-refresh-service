<?php
namespace FTS\JwtRefreshService\Api;

use Magento\Framework\Exception\AuthorizationException;
use Magento\Framework\Exception\InvalidArgumentException;

interface JwtRefreshServiceInterface
{
    /**
     * @return string JWT with updated expiry time
     * @throws AuthorizationException when current request has no or invalid bearer token
     * @throws InvalidArgumentException when current request bearer token is not a JWT
     */
    public function refreshAdminToken() : string;
}
