const instance = require('../../helpers/weak_cache');
const {
    InvalidClient, InvalidRequestObject,
} = require('../../helpers/errors');

/*
 * Validates the incoming nonce from request
 *
 * @throws: invalid_request
 */

module.exports = async function checkNonce(ctx, next) {
    const { query: { token: { agent_pub_key, nonce } } } = ctx;
    let adapter;

    function getAdapter() {
      if (!adapter) adapter = new (instance(ctx.oidc.provider).Adapter)('Nonce');
      return adapter;
    }

    try {
        const now = new Date().getTime();
        const currentNonce = new Date(Number(nonce)).getTime();

        const adapter = getAdapter();
        const foundNonce = await adapter.find(agent_pub_key);

        const nonceExpired = (now - currentNonce) > (30 * 1000);

        const nonceRepeated = foundNonce ? new Date(Number(foundNonce.nonce)).getTime() >= currentNonce : false;
  
        if (isNaN(currentNonce) || nonceExpired || nonceRepeated) {
            throw err;
        }

    } catch (e) {
        throw new InvalidRequestObject('Nonce is not valid');
    }

    await adapter.upsert(agent_pub_key, {nonce}, 30);
    ctx.query = ctx.query.token;

    return next();
};
