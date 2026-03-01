import express from 'express';
import { LoginBackend, FusionAuth } from '@gurupras/login-backend';
import SimpleCrypto from '@gurupras/simple-crypto';
import fs from 'fs';

const kickstart = JSON.parse(fs.readFileSync('./kickstart.json', 'utf8'));

const port = process.env.PORT || 3000;
const fusionAuthHost = process.env.FUSIONAUTH_HOST || 'http://login-backend-test-fusionauth:9011';
const apiKey = kickstart.variables.apiKey;
const tenantID = kickstart.variables.defaultTenantId;
const applicationID = kickstart.variables.applicationId;
const clientID = kickstart.variables.applicationId
const clientSecret = kickstart.variables.clientSecret
const encryptionPassphrase = process.env.ENCRYPTION_PASSPHRASE || 'abcdefghabcdefghabcdefgh';
const simpleCrypto = new SimpleCrypto({
  algorithm: 'aes-256-cbc',
  passphrase: encryptionPassphrase
});

const log = console;

async function main() {
  const fusionAuth = new FusionAuth({
    host: fusionAuthHost,
    apiKey,
    tenantID,
    clientID
  });

  const app = express();
  const router = express.Router();

  const config = {
    fusionAuthOrigin: fusionAuthHost,
    applicationID,
    clientID,
    clientSecret,
    scope: 'openid offline_access',
    tenantID,
    social: {},
    webhookSecret: 'secret'
  };

  const loginBackend = new LoginBackend(fusionAuth, router, simpleCrypto, config, log);
  loginBackend.setupRoutes(router);

  app.use(router);
  app.listen(port, () => {
    log.info(`Server listening on port ${port}`);
  });

  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

	// Explicit endpoint to force an email to be verified
	app.get('/verify/:email', async (req, res) => {
		const { params: { email } } = req
		try {
			await loginBackend.updateEmailVerificationState(email, true)
			res.send('OK')
		} catch (e) {
			console.error('Error when verifying email', e)
			res.status(500).send(e.message)
		}
	})
}

main().catch(err => {
  log.error('Failed to start server', err);
  process.exit(1);
});
