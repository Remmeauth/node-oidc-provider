/* eslint-disable prefer-rest-params */

const { strict: assert } = require('assert');

const hash = require('object-hash');
const assign = require('lodash/assign');
const get = require('lodash/get');

const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const base64url = require('../helpers/base64url');
const ssHandler = require('../helpers/samesite_handler');

const hasFormat = require('./mixins/has_format');

const NON_REJECTABLE_CLAIMS = new Set(['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss']);
const NON_REJECTABLE_SCOPES = new Set(['openid']);

module.exports = function getSession(provider) {
  function setterSetValidation(values, forbiddenMembers = [], ignoredMembers = []) {
    if (Array.isArray(values)) {
      values = new Set(values); // eslint-disable-line no-param-reassign
    } else if (!(values instanceof Set)) {
      throw new Error('expected Array or Set');
    }

    forbiddenMembers.forEach((forbidden) => {
      if (values.has(forbidden)) {
        throw new Error(`${forbidden} cannot be rejected`);
      }
    });

    ignoredMembers.forEach(Set.prototype.delete.bind(values));

    return [...values];
  }

  function getterSetTransformation(value) {
    if (Array.isArray(value)) {
      return new Set(value);
    }

    if (typeof value === 'undefined') {
      return new Set();
    }

    /* istanbul ignore next */
    throw new Error('expected Array to be stored');
  }

  let adapter;
  function getAdapter() {
    if (!adapter) adapter = new (instance(provider).Adapter)('Apps');
    return adapter;
  }

  class Session extends hasFormat(provider, 'Session', instance(provider).BaseModel) {
    constructor(payload) {
      super(payload);
      if (!payload) {
        Object.defineProperty(this, 'new', { value: true });
      }
      this.uid = this.uid || nanoid();
      this.jti = this.jti || nanoid();
    }

    get id() {
      return this.jti;
    }

    set id(value) {
      this.jti = value;
    }

    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'uid',
        'acr',
        'amr',
        'account',
        'loginTs',
        'transient',
        'state',
        'authorizations',
        'apps',
      ];
    }

    static async findByUid(uid) {
      const stored = await this.adapter.findByUid(uid);
      try {
        assert(stored);
        const payload = await this.verify(undefined, stored, { foundByReference: true });
        return new this(payload);
      } catch (err) {
        return undefined;
      }
    }

    static async getAll(ctx) {
      const context = ctx.oidc ? ctx.oidc : provider.app.createContext(ctx.req, ctx.res);

      let cookieSessionId = get(context, 'verifyedData.sessionId')

      let sessions = [];
      if (cookieSessionId) {
        sessions = await this.findAll(cookieSessionId);
      }

      return sessions;
    }

    static async get(ctx) {
      const context = ctx.oidc ? ctx.oidc : provider.app.createContext(ctx.req, ctx.res);

      let cookieSessionId;
      let cookieProfileId;
      if (process.env.SESSION_MODE === 'token') {
        cookieSessionId = get(context, 'verifyedData.sessionId')
        cookieProfileId = get(context, 'verifyedData.profileId')
      } else {
        cookieSessionId = ssHandler.get(
          context.cookies,
          provider.cookieName('session'),
          instance(provider).configuration('cookies.long'),
        );
      }

      let session;

      if (cookieSessionId && cookieProfileId) {
        session = await this.find(cookieSessionId, {}, cookieProfileId);
        if (!session) {
          session = await this.find(cookieSessionId);
        }

        if (session) {
          session.apps = {};
          const appAdapter = getAdapter();
          const keys = Object.keys(session.authorizations || {});
          for (const clientId of keys) {
            const app = await appAdapter.find(`${cookieProfileId}:${clientId}`);
            session.apps[clientId] = app;
          }
        }
      } else if (cookieSessionId) {
        session = await this.find(cookieSessionId);
      }

      if (!session) {
        if (cookieSessionId) {
          // underlying session was removed since we have a session id in cookie, let's assign an
          // empty data so that session.new is not true and cookie will get written even if nothing
          // gets written to it
          session = new this({});

          if (process.env.SESSION_MODE === 'token') {
            session = new this({jti: cookieSessionId});
          } 
        } else {
          session = new this();
        }
      }

      if (ctx.oidc instanceof provider.OIDCContext) {
        ctx.oidc.entity('Session', session);
      }

      return session;
    }

    async save(ttl = instance(provider).configuration('cookies.long.maxAge') / 1000) {
      // one by one adapter ops to allow for uid to have a unique index

      delete this.apps;

      if (this.oldId) {
        await this.adapter.destroy(this.oldId);
      }

      const result = await super.save(ttl);

      this.touched = false; // TODO:

      return result;
    }

    async destroy() {
      await super.destroy();
      this.destroyed = true; // TODO:
    }

    resetIdentifier() {
      this.oldId = this.id;
      this.id = nanoid();
      this.touched = true;
    }

    accountId() {
      return this.account;
    }

    authTime() {
      return this.loginTs;
    }

    past(age) {
      const maxAge = +age;

      if (this.loginTs) {
        return epochTime() - this.loginTs > maxAge;
      }

      return true;
    }

    authorizationFor(clientId) {
      // the call will not set, let's not modify the session object
      if (arguments.length === 1 && !this.authorizations) {
        return {};
      }

      this.authorizations = this.authorizations || {};
      if (!this.authorizations[clientId]) {
        this.authorizations[clientId] = {};
      }

      return this.authorizations[clientId];
    }

    stateFor(clientId) {
      return base64url.encodeBuffer(hash(this.authorizationFor(clientId), {
        algorithm: 'sha256',
        ignoreUnknown: true,
        unorderedArrays: true,
        unorderedSets: true,
        encoding: 'buffer',
      }));
    }

    sidFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.sid = value;
        return undefined;
      }

      return authorization.sid;
    }

    grantIdFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.grantId = value;
        return undefined;
      }

      return authorization.grantId;
    }

    metaFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.meta = value;
        return undefined;
      }

      return authorization.meta;
    }

    acceptedScopesFor(clientId) {
      const accepted = new Set(this.promptedScopesFor(clientId));
      this.rejectedScopesFor(clientId).forEach(Set.prototype.delete.bind(accepted));
      return accepted;
    }

    acceptedClaimsFor(clientId) {
      const accepted = new Set(this.promptedClaimsFor(clientId));
      this.rejectedClaimsFor(clientId).forEach(Set.prototype.delete.bind(accepted));
      return accepted;
    }

    promptedScopesFor(clientId, scopes) {
      if (process.env.SESSION_MODE === 'token') {
        return getterSetTransformation(get(this, ['apps', clientId, 'promptedScopes']));
      } else {
        const authorization = this.authorizationFor(...arguments);

        if (scopes) {
          if (authorization.promptedScopes) {
            authorization.promptedScopes = [
              ...new Set([
                ...authorization.promptedScopes,
                ...setterSetValidation(scopes),
              ]),
            ];
            return undefined;
          }

          authorization.promptedScopes = setterSetValidation(scopes);
          return undefined;
        }


        return getterSetTransformation(authorization.promptedScopes);
      }
    }

    promptedClaimsFor(clientId, claims) {
      if (process.env.SESSION_MODE === 'token') {
        return getterSetTransformation(get(this, ['apps', clientId, 'promptedClaims']));
      } else {
        const authorization = this.authorizationFor(...arguments);

        if (claims) {
          if (authorization.promptedClaims) {
            authorization.promptedClaims = [
              ...new Set([
                ...authorization.promptedClaims,
                ...setterSetValidation(claims),
              ]),
            ];
            return undefined;
          }

          authorization.promptedClaims = setterSetValidation(claims);
          return undefined;
        }

        return getterSetTransformation(authorization.promptedClaims);
      }
    }

    rejectedScopesFor(clientId, scopes, replace = false) {  
      if (process.env.SESSION_MODE === 'token') {
        return getterSetTransformation(get(this, ['apps', clientId, 'rejectedScopes']));
      } else {
        const authorization = this.authorizationFor(...arguments);

        if (scopes) {
          if (replace || !authorization.rejectedScopes) {
            authorization.rejectedScopes = setterSetValidation(scopes, NON_REJECTABLE_SCOPES);
            return undefined;
          }
  
          authorization.rejectedScopes = [
            ...new Set([
              ...authorization.rejectedScopes,
              ...setterSetValidation(scopes, NON_REJECTABLE_SCOPES),
            ]),
          ];
          return undefined;
        }
  
        return getterSetTransformation(authorization.rejectedScopes);
      }
    }

    rejectedClaimsFor(clientId, claims, replace = false) {
      if (process.env.SESSION_MODE === 'token') {
        return getterSetTransformation(get(this, ['apps', clientId, 'rejectedClaims']));
      } else {
        const authorization = this.authorizationFor(...arguments);

        if (claims) {
          if (replace || !authorization.rejectedClaims) {
            authorization.rejectedClaims = setterSetValidation(claims, NON_REJECTABLE_CLAIMS);
            return undefined;
          }

          authorization.rejectedClaims = [
            ...new Set([
              ...authorization.rejectedClaims,
              ...setterSetValidation(claims, NON_REJECTABLE_CLAIMS),
            ]),
          ];
          return undefined;
        }

        return getterSetTransformation(authorization.rejectedClaims);
      }
    }

    appPromptedScopesFor(authorization, scopes) { //APP
      if (scopes) {
        if (authorization.promptedScopes) {
          return [
            ...new Set([
              ...authorization.promptedScopes,
              ...setterSetValidation(scopes),
            ]),
          ];
        }
        return setterSetValidation(scopes);
      }
      return getterSetTransformation(authorization.promptedScopes);
    }

    appPromptedClaimsFor(authorization, claims) { //APP
      if (claims) {
        if (authorization.promptedClaims) {
          return [
            ...new Set([
              ...authorization.promptedClaims,
              ...setterSetValidation(claims),
            ]),
          ];
        }
        return setterSetValidation(claims);
      }
      return getterSetTransformation(authorization.promptedClaims);
    }

    appRejectedScopesFor(authorization, scopes, replace = false) { //APP

      if (replace || !authorization.rejectedScopes) {
        return setterSetValidation(scopes, NON_REJECTABLE_SCOPES);
      }

      return [
        ...new Set([
          ...authorization.rejectedScopes,
          ...setterSetValidation(scopes, NON_REJECTABLE_SCOPES),
        ]),
      ];
    }

    appRejectedClaimsFor(authorization, claims, replace = false) { //APP

      if (replace || !authorization.rejectedClaims) {
        return setterSetValidation(claims, NON_REJECTABLE_CLAIMS);
      }

      return [
        ...new Set([
          ...authorization.rejectedClaims,
          ...setterSetValidation(claims, NON_REJECTABLE_CLAIMS),
        ]),
      ];
    }

    ensureClientContainer(clientId) {
      if (!this.sidFor(clientId)) {
        this.sidFor(clientId, nanoid());
      }

      if (!this.grantIdFor(clientId)) {
        this.grantIdFor(clientId, nanoid());
      }
    }

    loginAccount(details) {
      const {
        transient = false, account, loginTs = epochTime(), amr, acr,
      } = details;

      assign(
        this,
        {
          account, loginTs, amr, acr,
        },
        transient ? { transient: true } : undefined,
      );
    }
  }

  return Session;
};
