import createHttpError from 'http-errors';
import { Session } from '../models/session.js';
import { User } from '../models/user.js';

export const authenticate = async (req, res, next) => {
  // 1. Chech is accessToken exists
  if (!req.cookies.accessToken) {
    next(createHttpError(401, 'Missing access token'));
    return;
  }

  // 2. If access token exists, looking for sesion
  const session = await Session.findOne({
    accessToken: req.cookies.accessToken,
  });

  // 3. If didn't find a sesion , returns an error
  if (!session) {
    next(createHttpError(401, 'Session not found'));
    return;
  }

  // 4. Checking the validity period of the access token
  const isAccessTokenExpired =
    new Date() > new Date(session.accessTokenValidUntil);

  if (isAccessTokenExpired) {
    return next(createHttpError(401, 'Access token expired'));
  }

  // 5. If the token is valid and the session exists, we look for the user.
  const user = await User.findById(session.userId);

  // 6. If user didn't find
  if (!user) {
    next(createHttpError(401));
    return;
  }

  // 7. If the user exists, we add them to the request
  req.user = user;

  // 8. Hand over control
  next();
};
