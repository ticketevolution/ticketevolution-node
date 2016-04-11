# ticketevolution-node
A JavaScript client for the Ticket Evolution API.

[Full API documentation](https://ticketevolution.atlassian.net/wiki/display/API/Current+Version) is a available here.

The client is built atop [isomorphic-fetch](https://github.com/matthew-andrews/isomorphic-fetch) so it can be used in both the browser as well as on a node server.

However, **DO NOT USE IN THE BROWSER FOR PRODUCTION** as this would reveal your API Secret Key.
Browser support is merely provided to enable local & sandbox experiments.

## Installation

```bash
npm install -S ticketevolution-node
```

## Usage

```es6
const TevoClient = require('ticketevolution-node');
const API_TOKEN = 'XXXXXXXXXX';
const API_SECRET_KEY = 'XXXXXXXXXX';

const tevoClient = new TevoClient({
  apiToken:     API_TOKEN,
  apiSecretKey: API_SECRET_KEY,
});
```

The client returns an [ES6 Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise).

### Performing GET

```es6
tevoClient.getJSON('https://api.ticketevolution.com/v9/events').then((json) => {
    console.log('Got events from API.', json.total_entries, json.events);
}).catch((err) => {
    console.err(err);
});
```

### Performing POST

```es6
const postBody = {
    id: 12345,
    internal_notes: "Example private notes.",
};

tevoClient.postJSON('https://api.ticketevolution.com/v9/ticket_groups', postBody).then((json) => {
    console.log('Updated ticket group 12345.');
}).catch((err) => {
    console.err(err);
});
```

### Manually Generate a Signature

This may be useful for debugging.

```es6
const signature = TevoClient.makeSignatureFromParts({
  hostname: 'api.ticketevolution.com',
  method: 'GET',
  path: '/v9/orders',
  querystring: 'per_page=100&updated_at.gte=2015-08-21T01%3A44%3A18Z',
  secret: 'XXXXXXXXXXXXXXXXXXXXXXXX'
});
```

## Running Tests

```bash
TEVO_API_TOKEN=XXXXXXXXXX TEVO_API_SECRET_KEY=XXXXXXXXXX npm test
```