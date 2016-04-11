'use strict';

const crypto = require('crypto');
const fetch = require('isomorphic-fetch');
const Qs = require('qs');

const SIGNATURE_ALGORITHM = 'sha256';
const SIGNATURE_ENCODING = 'base64';

const queryStringToObject = (s) => {
  const obj = Qs.parse(s);
  return obj;
};

const queryObjectToString = (obj) => {
  const parts = [];
  let keys = Object.keys(obj);
  keys = keys.sort();
  keys.forEach((key) => {
    const subObj = {};
    subObj[key] = obj[key];
    const part = Qs.stringify(subObj, { arrayFormat: 'brackets' });
    parts.push(part);
  });
  return parts.join('&');
};

class TevoClient {

  constructor(options) {
    if (!options.apiToken) {
      console.error('You must provide tevoAuth.Client with a valid apiToken.');
    }
    if (!options.apiSecretKey) {
      console.error('You must provide tevoAuth.Client with a valid apiSecretKey.');
    }
    this.apiToken = options.apiToken;
    this.apiSecretKey = options.apiSecretKey;
  }

  static makeSignatureFromParts(options) {
    const defaultOptions = {
      hostname:     'localhost',
      method:       'GET',
      path:         '/',
      querystring:  ''
    };
    options = Object.assign({}, defaultOptions, options);
    let querystring = options.querystring;
    if (options.method == 'GET') {
      querystring = queryStringToObject(querystring);
      querystring = queryObjectToString(querystring);
    }
    let stringToSign = `${ options.method } ${ options.hostname }${ options.path }?${ querystring }`;
    const signature = crypto.createHmac(SIGNATURE_ALGORITHM, options.secret).update(stringToSign).digest(SIGNATURE_ENCODING);
    return signature;
  }

  static makeSignature(method, href, secret) {
    // http://stackoverflow.com/questions/736513/how-do-i-parse-a-url-into-hostname-and-path-in-javascript
    var reURLInformation = new RegExp([
      '^(https?:)//',               // protocol
      '(([^:/?#]*)(?::([0-9]+))?)', // host (hostname and port)
      '(/[^?#]*)',                  // pathname
      '(\\??)',                     // question mark
      '([^#]*|)',                   // search
      '(#.*|)$'                     // hash
    ].join(''));
    var match = href.match(reURLInformation);
    if (!match) {
      console.error('makeSignature()', 'Invalid href.');
      return;
    }
    const hostname = match[3];
    //const isHttps = (match[1] == HTTPS); Ignored when computing signature.
    const path = match[5];
    //const port = match[4]; Ignored when computing signature.
    const querystring = match[7];
    return TevoClient.makeSignatureFromParts({
      hostname:     hostname,
      method:       method,
      path:         path,
      querystring:  querystring,
      secret:       secret,
    });
  }

  generateHeaders(options) {
    const sig = TevoClient.makeSignature(options.method, options.href, this.apiSecretKey);
    return {
      'X-Token':      this.apiToken,
      'X-Signature':  sig,
      'Accept':       'application/vnd.ticketevolution.api+json; version=8',
    }
  }

  postJSON(href, body) {
    if (!body) body = {};
    const headers = this.generateHeaders({
      href:   `${href}?${JSON.stringify(body)}`,
      method: 'POST',
    });
    return fetch(href, {
      headers: headers,
      body:    JSON.stringify(body),
      method:  'POST',
    })
    .then((response) => {
      return response.json();
    })
    .then((json) => {
      return json;
    });
  }

  getJSON(href) {
    const headers = this.generateHeaders({
      href:   href,
      method: 'GET',
    });
    return fetch(href, {
      headers: headers,
    })
    .then((response) => {
      return response.json();
    })
    .then((json) => {
      return json;
    });
  }

}

module.exports = TevoClient;