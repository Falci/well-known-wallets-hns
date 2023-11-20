const hdns = require('hdns');
const https = require('https');

export const init = (...hsd) => hdns.setServers(hsd);

class TLSAError extends Error {
  static E_LARGE = 'ELARGE';
  static E_INSECURE = 'EINSECURE';

  constructor(message = 'Invalid TLSA', code = E_INSECURE) {
    super(message);
    this.code = code;
  }
}

const MAX_LENGTH = 90;

const verifyTLSA = async (cert, host) => {
  try {
    const tlsa = await hdns.resolveTLSA(host, 'tcp', 443);
    const valid = hdns.verifyTLSA(tlsa[0], cert.raw);

    return valid;
  } catch (e) {
    console.error(e);
    return false;
  }
};

export async function getAddress(host) {
  return new Promise(async (resolve, reject) => {
    const options = {
      rejectUnauthorized: false,
      lookup: hdns.legacy,
      host,
      port: 443,
      method: 'GET',
      path: '/.well-known/wallets/HNS',
      agent: false,
    };

    const req = https.request(options, (res) => {
      res.setEncoding('utf8');

      let data = '';

      res.on('data', (chunk) => {
        const newLine = chunk.indexOf('\n');
        if (newLine >= 0) {
          req.destroy();
          chunk = chunk.slice(0, newLine);
        }

        if (data.length + chunk.length > MAX_LENGTH) {
          if (!req.destroyed) {
            req.destroy();
          }
          throw new TLSAError('response too large', TLSAError.E_LARGE);
        }

        data += chunk;
      });

      res.on('end', async () => {
        const cert = res.socket.getPeerCertificate(false);
        const dane = await verifyTLSA(cert, host);

        if (!dane) {
          throw new TLSAError('invalid DANE', TLSAError.E_INSECURE);
        }

        if (res.statusCode >= 400) {
          throw new TLSAError(res.statusMessage, res.statusCode);
        }

        return resolve(data.trim());
      });
    });

    req.on('error', reject);
    req.end();
  });
}
