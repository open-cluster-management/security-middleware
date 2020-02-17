# security-middleware
Security middleware for OCP oauth server
## Usage
### Production
No configuration is required to run it in production mode.
### Development
To run it locally, you will need
```
OAUTH2_CLIENT_ID
OAUTH2_CLIENT_SECRET
OAUTH2_REDIRECT_URL
process.env.API_SERVER_URL
process.env.SERVICEACCT_TOKEN
```

To protect `ui`
```javascript
const inspect = require('security-middleware')
router.all(['/', '/*'], inspect.ui(), app)
```
To protect `api`
```javascript
const inspect = require('security-middleware')
router.all(['/', '/*'], inspect.app, app)
```