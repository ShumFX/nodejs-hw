import bcrypt from "bcrypt";
import createHttpError from 'http-errors';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.js';
// session imports
import { createSession, setSessionCookies } from '../services/auth.js';
import { Session } from "../models/session.js";
import { sendEmail } from '../utils/sendMail.js';
import handlebars from 'handlebars';
import fs from 'fs/promises';
import path from 'path';

// registration

export const registerUser = async (req, res, next) => {
  const { email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(createHttpError(400, 'Email in use'));
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await User.create({
    email,
    password: hashedPassword,
  });

  const newSession = await createSession(newUser._id);

  setSessionCookies(res, newSession);

  res.status(201).json(newUser);
};

// login
export const loginUser = async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return next(createHttpError(401, 'User not found'));
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return next(createHttpError(401, 'Invalid credentials'));
  }

  await Session.deleteOne({ userId: user._id });

  const newSession = await createSession(user._id);

  setSessionCookies(res, newSession);

  res.status(200).json(user);
};

export const logoutUser = async (req, res) => {
  const { sessionId } = req.cookies;

  if (sessionId) {
    await Session.deleteOne({ _id: sessionId });
  }

  res.clearCookie('sessionId');
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  res.status(204).send();
};

export const refreshUserSession = async (req, res, next) => {

  const session = await Session.findOne({
    _id: req.cookies.sessionId,
    refreshToken: req.cookies.refreshToken,
  });


  if (!session) {
    return next(createHttpError(401, 'Session not found'));
  }

  const isSessionTokenExpired =
    new Date() > new Date(session.refreshTokenValidUntil);

  if (isSessionTokenExpired) {
    return next(createHttpError(401, 'Session token expired'));
  }

  await Session.deleteOne({
    _id: req.cookies.sessionId,
    refreshToken: req.cookies.refreshToken,
  });

  const newSession = await createSession(session.userId);
  setSessionCookies(res, newSession);

  res.status(200).json({
    message: 'Session refreshed',
  });
};

// Request reset password email
export const requestResetEmail = async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  
  // Завжди повертаємо 200, навіть якщо користувача не існує
  // Це запобігає enumeration атакам
  if (!user) {
    res.status(200).json({
      message: 'If the email exists, a reset link has been sent',
    });
    return;
  }

  // Генеруємо JWT токен з ID та email користувача
  const resetToken = jwt.sign(
    { 
      id: user._id,
      email: user.email 
    },
    process.env.JWT_SECRET,
    { expiresIn: '15m' } // 15 хвилин
  );

  // Читаємо HTML шаблон
  const templatePath = path.join(process.cwd(), 'src', 'templates', 'reset-password-email.html');
  const templateSource = await fs.readFile(templatePath, 'utf-8');

  // Компілюємо шаблон з handlebars
  const template = handlebars.compile(templateSource);
  
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
  
  const html = template({
    name: user.username || user.email,
    link: resetUrl,
  });

  // Відправляємо email
  await sendEmail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'Password Reset Request',
    html: html,
  });

  res.status(200).json({
    message: 'If the email exists, a reset link has been sent',
  });
};

// Reset password
export const resetPassword = async (req, res, next) => {
  const { token, password } = req.body;

  try {
    // Верифікуємо JWT токен
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Отримуємо ID та email з payload токена
    const { id, email } = decoded;

    // Знаходимо користувача за ID та email
    const user = await User.findOne({ _id: id, email });

    if (!user) {
      return next(createHttpError(401, 'Token is invalid or has expired'));
    }

    // Хешуємо новий пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Оновлюємо пароль
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({
      message: 'Password has been reset successfully',
    });
  } catch (error) {
    // Якщо токен невалідний або прострочений
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return next(createHttpError(401, 'Token is invalid or has expired'));
    }
    throw error;
  }
};
