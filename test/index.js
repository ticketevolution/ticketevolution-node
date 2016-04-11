'use strict';
const assert = require('assert');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const expect = chai.expect;
const should = chai.should();
chai.use(chaiAsPromised);

const TevoClient = require('../TevoClient');
const API_ROOT_URL = 'https://api.ticketevolution.com';

describe('TevoClient', () => {

  let tevoClient;

  // Runs before all tests.
  before((done) => {
    const apiToken = process.env.TEVO_API_TOKEN;
    const apiSecretKey = process.env.TEVO_API_SECRET_KEY;
    if (!apiToken || !apiSecretKey) {
      return done(`
        API credentials not provided as arguments.\n
        You must provide your Ticket Evolution API Token, and API Secret Key as params to the test.
      `);
    }
    assert(apiToken, 'Using ' + apiToken + ' as API Token.');
    assert(apiSecretKey, 'Using ' + apiSecretKey + ' as API Secret Key.');

    tevoClient = new TevoClient({
      apiToken: apiToken,
      apiSecretKey: apiSecretKey,
    });

    done();
  });

  it('Should GET events.', (done) => {
    const promise = tevoClient.getJSON(`${ API_ROOT_URL }/v9/events`);
    promise.then((json) => {
      assert(json.events.length > 0, 'Events were returned');
      done();
    }, (err) => {
      done(err);
    });

    // Alternate Syntaxes:
    // SHOULD) promise.should.eventually.exist.notify(done);
    // EXPECT) expect(promise).to.eventually.exist.notify(done);
  });

  it('Should POST authentication.', (done) => {
    const promise = tevoClient.postJSON(`${ API_ROOT_URL }/v9/users/authenticate`, {
      email: 'foo@bar.com',
      password: 'foo',
    });
    promise.then((json) => {
      assert(json, 'Authentication responded.');
      done();
    }, (err) => {
      done(err);
    });
  });

});