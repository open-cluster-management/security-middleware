# security-middleware
Security middleware for OCP oauth server
## Usage

Following environment variables are required to use this module
```
OAUTH2_CLIENT_ID
OAUTH2_CLIENT_SECRET
OAUTH2_REDIRECT_URL
```
To run it locally, you will also need
```
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