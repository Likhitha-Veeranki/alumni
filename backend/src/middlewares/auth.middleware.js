
const jwt = require('jsonwebtoken');
const userModel = require('../models/user.model');

const verifyToken = async (req, res, next) => {
  let token;

  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  if (!token && req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({
      message: 'Authentication required'
    });
  }

  try {
    const decode = jwt.verify(token, process.env.JWT_SECRET);

    const user = await userModel.findById(decode.id);

    if (!user) {
      return res.status(401).json({
        message: 'User not found'
      });
    }

    // Check whether the JWT has been revoked
    const currentVersion = user.tokenVersion ?? 0;

    if (decode.tokenVersion !== currentVersion) {
      return res.status(401).json({
        message: 'Token has been revoked. Please login again.'
      });
    }

    req.user = user;
    next();

  } catch (err) {
    return res.status(401).json({
      message: 'Token is not valid'
    });
  }
};

module.exports = verifyToken;

