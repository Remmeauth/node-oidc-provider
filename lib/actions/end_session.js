const crypto = require('crypto');
const url = require('url');
const set = require('lodash/set');

const { InvalidClient, InvalidRequest, OIDCProviderError } = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');
const rejectDupes = require('../shared/reject_dupes');
const bodyParser = require('../shared/conditional_body');
const paramsMiddleware = require('../shared/assemble_params');
const sessionMiddleware = require('../shared/session');
const revokeGrant = require('../helpers/revoke_grant');
const noCache = require('../shared/no_cache');
const ssHandler = require('../helpers/samesite_handler');
const formPost = require('../response_modes/form_post');
const checkJWT = require('../actions/authorization/check_jwt');
const checkNonce = require('../actions/authorization/check_nonce');

const contentType = process.env.SESSION_MODE === 'token' ? 'application/json' : 'application/x-www-form-urlencoded'
const parseBody = bodyParser.bind(undefined, contentType);

function frameFor(target) {
  return `<iframe src="${target}"></iframe>`;
}

let adapter;
function getAdapter(ctx) {
  if (!adapter) adapter = new (instance(ctx.oidc.provider).Adapter)('Apps');
  return adapter;
}

module.exports = {
  init: [
    noCache,
    sessionMiddleware,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['id_token_hint', 'post_logout_redirect_uri', 'state', 'ui_locales'])),
    rejectDupes.bind(undefined, {}),

    async function endSessionChecks(ctx, next) {
      const { params } = ctx.oidc;

      if (params.id_token_hint) {
        try {
          const idTokenHint = JWT.decode(params.id_token_hint);
          ctx.oidc.entity('IdTokenHint', idTokenHint);
        } catch (err) {
          throw new InvalidRequest(`could not decode id_token_hint (${err.message})`);
        }
        const { payload: { aud: clientId } } = ctx.oidc.entities.IdTokenHint;

        const client = await ctx.oidc.provider.Client.find(clientId);
        if (!client) {
          throw new InvalidClient('unrecognized id_token_hint audience', 'client not found');
        }
        try {
          await ctx.oidc.provider.IdToken.validate(params.id_token_hint, client);
        } catch (err) {
          if (err instanceof OIDCProviderError) {
            throw err;
          }

          throw new InvalidRequest(`could not validate id_token_hint (${err.message})`);
        }

        if (params.post_logout_redirect_uri) {
          if (!client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri)) {
            throw new InvalidRequest('post_logout_redirect_uri not registered');
          }
        }

        ctx.oidc.entity('Client', client);
      } else if (params.post_logout_redirect_uri !== undefined) {
        throw new InvalidRequest('post_logout_redirect_uri can only be used in combination with id_token_hint');
      }

      await next();
    },

    async function renderLogout(ctx, next) {
      // TODO: generic xsrf middleware to remove this
      const secret = crypto.randomBytes(24).toString('hex');

      ctx.oidc.session.state = {
        secret,
        clientId: ctx.oidc.client ? ctx.oidc.client.clientId : undefined,
        state: ctx.oidc.params.state,
        postLogoutRedirectUri: ctx.oidc.params.post_logout_redirect_uri || ctx.oidc.urlFor('end_session_success'),
      };

      const action = ctx.oidc.urlFor('end_session_confirm');

      if (ctx.oidc.session.accountId()) {
        ctx.type = 'html';
        ctx.status = 200;

        const formHtml = `<form id="op.logoutForm" method="post" action="${action}"><input type="hidden" name="xsrf" value="${secret}"/></form>`;
        await instance(ctx.oidc.provider).configuration('logoutSource')(ctx, formHtml);
      } else {
        await formPost(ctx, action, {
          xsrf: secret,
          logout: 'yes',
        });
      }

      await next();
    },
  ],

  removeProfile: [
    noCache,
    parseBody,
    async (ctx, next) => {
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.jwtVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.nonceVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.deviceVerifying(ctx, next, 'oidc');
    },

    async (ctx, next) => {
      const { chain_name, sub } =  ctx.oidc.body;

      const { features: { backchannelLogout }, deleteAccount } = instance(ctx.oidc.provider).configuration();

      if (!deleteAccount) throw new InvalidRequest('deleteAccount function not initialized');
      if (!sub)           throw new InvalidRequest('missing required parameter: sub');

      const profile = await ctx.oidc.provider.Account.findAccount(ctx, sub);

      if (!profile || !profile.accountId || profile.chain_name !== chain_name) { throw new InvalidRequest('profile not found') };

      await deleteAccount(ctx, sub);

      const connected_apps = await await getAdapter(ctx).getAll(profile.accountId);

      const app_items = connected_apps.map(key => key.replace(`oidc:Apps:`, ''));

      for (const item of app_items) {
        try {
          const [profile_id, client_id] = item.split(':');
          if ( !profile_id || !client_id ) { continue };

          const app = await getAdapter(ctx).find(item);

          if ( !app ) { continue };

          const { chainName, grants } = app;

          const client = await ctx.oidc.provider.Client.find(client_id);

          if (chainName === chain_name && client) {
            const sessions = await ctx.oidc.provider.Session.findAll(true, `*:${profile_id}`);
            
            for (const session of sessions) {
              const authorization = session.authorizationFor(client_id);

              if (authorization.sid) {

                const back = [];

                if (backchannelLogout.enabled && client.backchannelLogoutUri) {
                  back.push(client.backchannelLogout(profile_id, authorization.sid)
                    .then(() => {
                      ctx.oidc.provider.emit('backchannel.success', ctx, client, profile_id, authorization.sid);
                    }, (err) => {
                      ctx.oidc.provider.emit('backchannel.error', ctx, err, client, profile_id, authorization.sid);
                    }));
                }

                if ( authorization.grantId ) {
                  await revokeGrant(ctx.oidc.provider, client, authorization.grantId);
                  ctx.oidc.provider.emit('grant.revoked', ctx, authorization.grantId);
                }

                await Promise.all(back);
    
                delete session.authorizations[client_id];

                for (const authorization_client_id of Object.keys(session.authorizations)) {
                  meta = session.authorizations[authorization_client_id].meta
                  if (!meta) {
                    delete session.authorizations[authorization_client_id];
                  }
                }

                if (!Object.keys(session.authorizations).length) {
                  await session.destroy();
                } else {
                  await session.save();
                }
    
                ctx.oidc.provider.emit('end_sessions.success', {
                  agent: authorization.meta.agent,
                  profile: session.account,
                  client: client_id,
                  sid: authorization.sid,
                  chain_name,
                });
              }
            }

            if ( grants && Object.keys(grants).length) {
              const client = await ctx.oidc.provider.Client.find(client_id).catch(() => {});
              for (const grantId of Object.keys(grants)) {
                await revokeGrant(ctx.oidc.provider, client, grantId);
                ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
              }
            }

            await getAdapter(ctx).destroy(item);
          }
        } catch (e) {
          continue;
        }
      }

      ctx.body = {
        success: true
      }

      await next();
    },
  ],

  removeAccess: [
    noCache,
    parseBody,
    async (ctx, next) => {
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.jwtVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.nonceVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.deviceVerifying(ctx, next, 'oidc');
    },

    async (ctx, next) => {
      const { chain_name, app_items } =  ctx.oidc.body;

      const { features: { backchannelLogout } } = instance(ctx.oidc.provider).configuration();

      if (!app_items) throw new InvalidRequest('missing required parameter: app_items');

      for (const item of app_items) {
        try {
          const [profile_id, client_id] = item.split(':');
          if ( !profile_id || !client_id ) { continue };

          const app = await getAdapter(ctx).find(item);

          if ( !app ) { continue };

          const { chainName, grants } = app;

          const client = await ctx.oidc.provider.Client.find(client_id);

          if (chainName === chain_name && client) {
            const sessions = await ctx.oidc.provider.Session.findAll(true, `*:${profile_id}`);
            
            for (const session of sessions) {
              const authorization = session.authorizationFor(client_id);

              if (authorization.sid) {

                const back = [];

                if (backchannelLogout.enabled && client.backchannelLogoutUri) {
                  back.push(client.backchannelLogout(profile_id, authorization.sid)
                    .then(() => {
                      ctx.oidc.provider.emit('backchannel.success', ctx, client, profile_id, authorization.sid);
                    }, (err) => {
                      ctx.oidc.provider.emit('backchannel.error', ctx, err, client, profile_id, authorization.sid);
                    }));
                }

                if ( authorization.grantId ) {
                  await revokeGrant(ctx.oidc.provider, client, authorization.grantId);
                  ctx.oidc.provider.emit('grant.revoked', ctx, authorization.grantId);
                }

                await Promise.all(back);
    
                delete session.authorizations[client_id];

                for (const authorization_client_id of Object.keys(session.authorizations)) {
                  meta = session.authorizations[authorization_client_id].meta
                  if (!meta) {
                    delete session.authorizations[authorization_client_id];
                  }
                }

                if (!Object.keys(session.authorizations).length) {
                  await session.destroy();
                } else {
                  await session.save();
                }
    
                ctx.oidc.provider.emit('end_sessions.success', {
                  agent: authorization.meta.agent,
                  profile: session.account,
                  client: client_id,
                  sid: authorization.sid,
                  chain_name,
                });
              }
            }

            if ( grants && Object.keys(grants).length) {
              const client = await ctx.oidc.provider.Client.find(client_id).catch(() => {});
              for (const grantId of Object.keys(grants)) {
                await revokeGrant(ctx.oidc.provider, client, grantId);
                ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
              }
            }

            await getAdapter(ctx).destroy(item);
          }          
        } catch (e) {
          continue;
        }
      }

      ctx.body = {
        success: true
      }

      await next();
    },
  ],

  fromBackend: [
    noCache,
    parseBody,
    async (ctx, next) => {
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.jwtVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.nonceVerifying(ctx, next, 'oidc');
    },
    async (ctx, next) => { 
      await instance(ctx.oidc.provider).configuration().deviceAuthentication.deviceVerifying(ctx, next, 'oidc');
    },

    async (ctx, next) => {
      const { chain_name, session_items } =  ctx.oidc.body;

      const { features: { backchannelLogout } } = instance(ctx.oidc.provider).configuration();

      if (!session_items) throw new InvalidRequest('missing required parameter: session_items');

      for (const item of session_items) {
        try {
          const [id, client_id, authorization_id] = item.split('.');
          const [session_id, profile_id] = id.split(':');

          if ( !session_id || !client_id || !authorization_id ) { continue };

          const session = await ctx.oidc.provider.Session.find(session_id, false, profile_id);

          const { grantId, sid, meta } = session.authorizations[client_id];

          if ( sid === authorization_id && session.chainName() === chain_name ) {

            const back = [];

            const client = await ctx.oidc.provider.Client.find(client_id);

            if (client) {

              if (backchannelLogout.enabled && client.backchannelLogoutUri) {
                back.push(client.backchannelLogout(profile_id, sid)
                  .then(() => {
                    ctx.oidc.provider.emit('backchannel.success', ctx, client, profile_id, sid);
                  }, (err) => {
                    ctx.oidc.provider.emit('backchannel.error', ctx, err, client, profile_id, sid);
                  }));
              }

              if (grantId) {
                if (!session.authorizationFor(client_id).persistsLogout) {
                  await revokeGrant(ctx.oidc.provider, client, grantId);
                  ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
                } else {
                  const app = await getAdapter(ctx).find(`${session.account}:${client_id}`);
                  if (app) {
                    set(app, `grants[${grantId}]`, session.jti);
                    await getAdapter(ctx).upsert(`${session.account}:${client_id}`, app);
                  }
                }
              }

            }

            await Promise.all(back);

            delete session.authorizations[client_id];

            for (const authorization_client_id of Object.keys(session.authorizations)) {
              const authorization_meta = session.authorizations[authorization_client_id].meta
              if (!authorization_meta) {
                delete session.authorizations[authorization_client_id];
              }
            }

            if (!Object.keys(session.authorizations).length) {
              await session.destroy();
            } else {
              await session.save();
            }

            ctx.oidc.provider.emit('end_sessions.success', {
              agent: meta.agent,
              profile: session.account,
              client: client_id,
              sid,
              chain_name: session.chainName(),
            });

          };

        } catch (e) {
          continue;
        }
      }

      ctx.body = {
        success: true
      }

      await next();
    },
  ],

  confirm: [
    noCache,
    parseBody,
    checkJWT,
    checkNonce,
    sessionMiddleware,
    paramsMiddleware.bind(undefined, new Set(['xsrf', 'logout'])),
    rejectDupes.bind(undefined, {}),

    async function checkLogoutToken(ctx, next) {
      if (!ctx.oidc.session.state) {
        throw new InvalidRequest('could not find logout details');
      }
      if (ctx.oidc.session.state.secret !== ctx.oidc.params.xsrf) {
        throw new InvalidRequest('xsrf token invalid');
      }
      await next();
    },

    async function endSession(ctx, next) {
      const { oidc: { session, params } } = ctx;
      const { state } = session;

      const {
        features: { backchannelLogout, frontchannelLogout, sessionManagement },
        cookies: { long: { maxAge, expires, ...opts } },
      } = instance(ctx.oidc.provider).configuration();

      const front = [];

      if (backchannelLogout.enabled || frontchannelLogout.enabled) {
        const clientIds = Object.keys(session.authorizations || {});

        const back = [];

        for (const clientId of clientIds) { // eslint-disable-line no-restricted-syntax
          if (params.logout || clientId === state.clientId) {
            const client = await ctx.oidc.provider.Client.find(clientId); // eslint-disable-line no-await-in-loop, max-len
            if (client) {
              const sid = session.sidFor(client.clientId);
              if (client.backchannelLogoutUri) {
                const accountId = session.accountId();
                back.push(client.backchannelLogout(accountId, sid)
                  .then(() => {
                    ctx.oidc.provider.emit('backchannel.success', ctx, client, accountId, sid);
                  }, (err) => {
                    ctx.oidc.provider.emit('backchannel.error', ctx, err, client, accountId, sid);
                  }));
              }
              if (client.frontchannelLogoutUri) {
                const target = url.parse(client.frontchannelLogoutUri, true);
                target.search = null;
                if (client.frontchannelLogoutSessionRequired) {
                  Object.assign(target.query, {
                    sid,
                    iss: ctx.oidc.issuer,
                  });
                }
                front.push(url.format(target));
              }
            }
          }
        }

        await Promise.all(back);
      }

      if (state.clientId) {
        ctx.oidc.entity('Client', await ctx.oidc.provider.Client.find(state.clientId));
      }

      if (params.logout) {
        if (session.authorizations) {
          await Promise.all(
            Object.entries(session.authorizations).map(async ([clientId, { grantId }]) => {
              // 1) drop the grants for the client that requested a logout
              // 2) drop the grants without offline_access
              // Note: tokens that don't get dropped due to offline_access having being added
              // later will still not work, as such they will be orphaned until their TTL hits
              if (
                grantId
                && (
                  clientId === state.clientId
                  || !session.authorizationFor(clientId).persistsLogout
                )
              ) {
                const client = await ctx.oidc.provider.Client.find(clientId).catch(() => {});
                await revokeGrant(ctx.oidc.provider, client, grantId);
                ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
              }
            }),
          );
        }

        await session.destroy();

        if (sessionManagement.enabled) {
          // get all cookies matching _state.[clientId](.sig) and drop them
          const STATES = new RegExp(`${ctx.oidc.provider.cookieName('state')}\\.[^=]+=`, 'g');
          const cookieNames = ctx.get('cookie').match(STATES);
          if (cookieNames) {
            cookieNames.forEach((val) => {
              const name = val.slice(0, -1);
              if (!name.endsWith('.sig') && !name.endsWith('.legacy')) {
                ssHandler.set(
                  ctx.oidc.cookies,
                  name,
                  null,
                  opts,
                );
              }
            });
          }
        }

        ssHandler.set(
          ctx.oidc.cookies,
          ctx.oidc.provider.cookieName('session'),
          null,
          opts,
        );
      } else if (state.clientId) {
        const grantId = session.grantIdFor(state.clientId);
        if (grantId) {
          const client = await ctx.oidc.provider.Client.find(state.clientId).catch(() => {});
          await revokeGrant(ctx.oidc.provider, client, grantId);
          ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
        }
        session.state = undefined;
        if (session.authorizations) {
          delete session.authorizations[state.clientId];
        }
        if (sessionManagement.enabled) {
          ssHandler.set(
            ctx.oidc.cookies,
            `${ctx.oidc.provider.cookieName('state')}.${state.clientId}`,
            null,
            opts,
          );
        }
        session.resetIdentifier();
      }

      const uri = redirectUri(
        state.postLogoutRedirectUri,
        {
          ...(state.state != null ? { state: state.state } : undefined), // != intended
          ...(!params.logout && state.clientId ? { client_id: state.clientId } : undefined),
        },
      );

      ctx.oidc.provider.emit('end_session.success', ctx);

      if (front.length) {
        const frames = front.map(frameFor);
        await frontchannelLogout.logoutPendingSource(ctx, frames, uri);
      } else {
        if (process.env.SESSION_MODE === 'token') {
          ctx.body = {
            redirect_uri: uri
          }
        } else {
          ctx.redirect(uri);
        }
      }

      await next();
    },
  ],

  success: [
    noCache,
    paramsMiddleware.bind(undefined, new Set(['client_id'])),
    async function postLogoutSuccess(ctx) {
      if (ctx.oidc.params.client_id) {
        const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);
        if (!client) {
          throw new InvalidClient('client is invalid', 'client not found');
        }
        ctx.oidc.entity('Client', client);
      }
      await instance(ctx.oidc.provider).configuration('postLogoutSuccessSource')(ctx);
    },
  ],
};
