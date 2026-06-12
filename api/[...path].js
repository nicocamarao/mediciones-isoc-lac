const { handleRequest } = require('../server.js');

module.exports = async function vercelApiHandler(req, res) {
  const originalUrl = req.url || '/';
  const apiPrefix = '/api';
  if (originalUrl === apiPrefix || originalUrl.startsWith(`${apiPrefix}?`)) {
    req.url = '/';
    return handleRequest(req, res);
  }

  if (originalUrl.startsWith(`${apiPrefix}/`)) {
    req.url = originalUrl.slice(apiPrefix.length);
    return handleRequest(req, res);
  }

  req.url = originalUrl;
  return handleRequest(req, res);
};
