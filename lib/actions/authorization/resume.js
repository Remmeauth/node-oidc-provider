const url = require('url');

const upperFirst = require('lodash/upperFirst');
const camelCase = require('lodash/camelCase');
const isObjectLike = require('lodash/isObjectLike');

const nanoid = require('../../helpers/nanoid');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const Params = require('../../helpers/params');
const formPost = require('../../response_modes/form_post');
const ssHandler = require('../../helpers/samesite_handler');
const epochTime = require('../../helpers/epoch_time');

module.exports = async function resumeAction(whitelist, resumeRouteName, ctx, next) {
  const { maxAge, expires, ...cookieOptions } = instance(ctx.oidc.provider).configuration('cookies.short');

  let id;
  if (process.env.SESSION_MODE === 'token') {
    id = ctx.oidc.uid;
  } else {
    id = ssHandler.get(
      ctx.oidc.cookies,
      ctx.oidc.provider.cookieName('resume'),
      cookieOptions,
    );
  }

  if (!id || id !== ctx.oidc.uid) {
    throw new errors.SessionNotFound('authorization request has expired');
  }

  const interactionSession = await ctx.oidc.provider.Interaction.find(id);
  if (!interactionSession) {
    throw new errors.SessionNotFound('interaction session not found');
  }
  ctx.oidc.entity('Interaction', interactionSession);

  const {
    result,
    params: storedParams = {},
    signed = [],
    session: originSession,
  } = interactionSession;

  const { session } = ctx.oidc;

  if (originSession && originSession.uid && originSession.uid !== session.uid) {
    throw new errors.SessionNotFound('interaction session and authentication session mismatch');
  }

  if (
    result
    && result.login
    && session.account
    && session.account !== result.login.account
  ) {
    if (interactionSession.session && interactionSession.session.uid) {
      delete interactionSession.session.uid;
      await interactionSession.save(interactionSession.exp - epochTime());
    }

    session.state = {
      secret: nanoid(),
      clientId: storedParams.client_id,
      postLogoutRedirectUri: ctx.oidc.urlFor(ctx.oidc.route, ctx.params),
    };

    if (process.env.SESSION_MODE === 'token') {
      ctx.status = 200;
      ctx.body = {
        xsrf: session.state.secret,
        logout: 'yes',
      }
    } else {
      await formPost(ctx, ctx.oidc.urlFor('end_session_confirm'), {
        xsrf: session.state.secret,
        logout: 'yes',
      });
    }

    return;
  }

  await interactionSession.destroy();

  const params = new (Params(whitelist))(storedParams);
  ctx.oidc.params = params;
  ctx.oidc.signed = signed;
  ctx.oidc.redirectUriCheckPerformed = true;

  const clearOpts = {
    ...cookieOptions,
    path: url.parse(ctx.oidc.urlFor(resumeRouteName, {
      uid: ctx.oidc.uid,
      ...(ctx.params.user_code ? { user_code: ctx.params.user_code } : undefined),
    })).pathname,
  };
  ssHandler.set(
    ctx.oidc.cookies,
    ctx.oidc.provider.cookieName('resume'),
    null,
    clearOpts,
  );

  if (result && result.error) {
    const className = upperFirst(camelCase(result.error));
    if (errors[className]) {
      throw new errors[className](result.error_description);
    } else {
      ctx.throw(400, result.error, {
        error_description: result.error_description,
      });
    }
  }

  session.ensureClientContainer(params.client_id);

  if (result && result.login) {
    const {
      remember = true, account, chain_name = undefined, ts: loginTs, amr, acr,
    } = result.login;

    session.loginAccount({
      account, chain_name, loginTs, amr, acr, transient: !remember,
    });
  }

  let adapter;
  function getAdapter() {
    if (!adapter) adapter = new (instance(ctx.oidc.provider).Adapter)('Apps');
    return adapter;
  }

  if (result && result.consent) {
    const {
      rejectedClaims,
      rejectedScopes,
      replace = false,
    } = result.consent;

    if (process.env.SESSION_MODE === 'token') {
      const appAdapter = getAdapter();
      const authorization = await appAdapter.find(`${session.account}:${params.client_id}`) || {};

      session.apps = session.apps || {};
      session.apps[params.client_id] = session.apps[params.client_id] || {};

      session.apps[params.client_id].chainName =  session.chainName();

      if (rejectedClaims) {
        session.apps[params.client_id].rejectedClaims = session.appRejectedClaimsFor(authorization, rejectedClaims, replace) || [];
      }

      if (rejectedScopes) {
        session.apps[params.client_id].rejectedScopes = session.appRejectedScopesFor(authorization, rejectedScopes, replace) || [];
      }

      session.apps[params.client_id].promptedScopes = session.appPromptedScopesFor(authorization, ctx.oidc.requestParamScopes);
      session.apps[params.client_id].promptedClaims = session.appPromptedClaimsFor(authorization, ctx.oidc.requestParamClaims);

      await adapter.upsert(`${session.account}:${params.client_id}`, session.apps[params.client_id]);
    } else {
      if (rejectedClaims) {
        session.rejectedClaimsFor(params.client_id, rejectedClaims, replace);
      }
  
      if (rejectedScopes) {
        session.rejectedScopesFor(params.client_id, rejectedScopes, replace);
      }
  
      session.promptedScopesFor(params.client_id, ctx.oidc.requestParamScopes);
      session.promptedClaimsFor(params.client_id, ctx.oidc.requestParamClaims);
    }

  }

  if (result && isObjectLike(result.meta)) {
    session.metaFor(params.client_id, result.meta);
  }

  ctx.oidc.result = result;

  if (!session.new) {
    if (process.env.SESSION_MODE !== 'token') {
      session.resetIdentifier();
    } 
  }

  await next();
};
