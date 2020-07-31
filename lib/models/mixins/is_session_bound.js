const { strict: assert } = require('assert');

const instance = require('../../helpers/weak_cache');

const debug = require('debug')('oidc-provider:mixin:is_session_bound');

let adapter;
function getAdapter(provider) {
  if (!adapter) adapter = new (instance(provider).Adapter)('Apps');
  return adapter;
}


module.exports = (provider) => (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'sessionUid',
      'expiresWithSession',
    ];
  }

  static async find(...args) {
    const token = await super.find(...args);
    if (!token || !token.expiresWithSession) {
      return token;
    }

    let session = await provider.Session.findByUid(token.sessionUid);

    if (session && process.env.SESSION_MODE === 'token') {
      session.apps = {};
      const appAdapter = getAdapter(provider);
      const keys = Object.keys(session.authorizations || {});

      for (const clientId of keys) {
        const app = await appAdapter.find(`${session.account}:${clientId}`);
        session.apps[clientId] = app;
      }
    }

    try {
      assert(session, 'its related session was not found');

      // session is still for the same account
      assert.equal(token.accountId, session.accountId(), 'token and session principal are now different');

      // session is still the same grantId
      assert.equal(token.grantId, session.grantIdFor(token.clientId), 'client\'s token and session grantId are now different');

      // session still has all the scopes
      const accepted = session.acceptedScopesFor(token.clientId);
      assert([...token.scopes].every((x) => accepted.has(x)), 'token scopes are no longer granted on the session');
    } catch (err) {
      debug(`not returning ${this.name} ${token.jti} because it is session bound and ${err.message}`);
      return undefined;
    }

    return token;
  }
};
