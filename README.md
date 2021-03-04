[comment]: # ( Copyright Contributors to the Open Cluster Management project )

# security-middleware

Security middleware for the Openshift OAuth server

## Usage

### Production

No configuration is required to run it in production mode.

### Development

To run it locally, you will need to set following environment variables:
```bash
OAUTH2_CLIENT_ID      # OAuth Client ID
OAUTH2_CLIENT_SECRET  # OAuth Client Secret
OAUTH2_REDIRECT_URL   # Redirect URL
API_SERVER_URL        # Kubernetes API URL
SERVICEACCT_TOKEN     # Kubernetes Access Token
```
For more information about Openshift OAuth, see the [Openshift documentation](https://docs.openshift.com/container-platform/latest/authentication/configuring-internal-oauth.html#oauth-register-additional-client_configuring-internal-oauth)

### Use it

- To protect the `ui`:
  ```javascript
  const inspect = require('security-middleware')
  router.all(['/', '/*'], inspect.ui(), app)
  ```

- To protect the `api`:
  ```javascript
  const inspect = require('security-middleware')
  router.all(['/', '/*'], inspect.app, app)
  ```