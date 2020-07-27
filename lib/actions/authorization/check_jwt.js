var jwt = require('jsonwebtoken');
var jwtDecode = require('jwt-decode');

const { InvalidRequestObject } = require('../../helpers/errors');

/*
 * Validates the incoming jwt token from browser
 *
 * @throws: invalid_request
 */

const pem = (str) => {
    return `-----BEGIN PUBLIC KEY-----\n${str}\n-----END PUBLIC KEY-----`
}

module.exports = async function checkJWT(ctx, next) {
    try {
        const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
        const { token } = params;

        let data;
        const { alg } = jwtDecode(token, {header: true});
        const { agent_pub_key, profile_id }  = jwtDecode(token);

        if (!alg || !agent_pub_key) {
            throw err;
        }

        data = jwt.verify(token, pem(agent_pub_key));

        ctx.oidc.verifyedData = {
            sessionId: agent_pub_key,
            profileId: profile_id,
        }

        ctx.jwt_payload = data;
    } catch (e) {
        throw new InvalidRequestObject(`Request token is not valid`);
    }

    return next();
};
