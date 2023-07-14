# magento-jwt-refresh-service

Adds an API endpoint `POST /V1/integration/admin/token/refresh` to refresh the
JWT from the Authorization header. Does not currently do customer tokens but PRs
are welcome.

e.g.:

```
$ curl --json '{"username": "username", "password": "password"}' http://mysite.docker/rest/V1/integration/admin/token/
"eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJ1aWQiOjY4LCJ1dHlwaWQiOjIsImlhdCI6MTY4OTM1MDYxOCwiZXhwIjoxNjg5MzU0MjE4fQ.Y2J6BVDFzBjSWP8MtfEievFplU21YyG40h56CLDIo9c"

$ curl -XPOST --data "" -H "Authorization: Bearer eyJraWQiO<etc>" http://mysite.docker/rest/V1/integration/admin/token/refresh/
"eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJ1aWQiOjY4LCJ1dHlwaWQiOjIsImlhdCI6MTY4OTM1MDYxOCwiZXhwIjoxNjg5MzU0MjQ3fQ.7TM1LlZ-1ONAQroFO_HVJWCqdl-ig8CCV1Sl-D3eCoA"
```

## Shouldn't JWT be short lived and only extended using refresh tokens?

I guess. A typical recommendation is that refresh tokens should be valid for
seven days, so I will accept a PR which validates that the provided JWT was
not issued over 7 days ago. This module goes to the effort of ensuring that
refreshing the token does not update the issue date, so it should not be too
difficult to enforce a maximum age.

(You can use base64 -d on the above curl example to verify that the iat claims
of the two tokens are the same, but the expt claim is extended.)

## BYOT

If you aren't using bearer tokens but you are using JWT, you can provide a token to be refreshed like this:

```php
class Whatever
{
    public function __construct(
        private \FTS\JwtRefreshService\Api\JwtRefreshServiceInterfaceFactory $jwtRefreshServiceFactory
    ) {}

    public function refreshToken(string $token)
    {
        $jwtRefreshService = $this->jwtRefreshServiceFactory->create([
            'token' => $token
        ]);
        return $jwtRefreshService->refreshAdminToken();
    }
}
```

## Why so complicated

https://github.com/maaarghk/magento-jwt-refresh-service/blob/7827d6b2c5d227bc8f5cedd45615ef0e1b451ec2/src/Model/Api/JwtRefreshService.php#L48-L58


## Help

I am unlikely to fulfil any feature requests, so please provide a merge request
alongside any that you have.

MRs with tests also welcome - it should be straightforward enough to verify the
token returned has the same claims and user context, and that the refreshed
token still validates.