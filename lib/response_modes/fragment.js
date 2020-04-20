const formatUri = require('../helpers/redirect_uri');

module.exports = (ctx, redirectUri, payload) => {
  const uri = formatUri(redirectUri, payload, 'fragment');
  if (process.env.SESSION_MODE === 'token') {
    ctx.body = {
      redirect_uri: uri
    }
  } else {
    ctx.redirect(uri);
  }
};
