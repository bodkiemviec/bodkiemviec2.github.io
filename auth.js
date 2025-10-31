const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
const COOKIE_SECURE = (process.env.COOKIE_SECURE === 'true');

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Register
router.post('/register',
  body('username').isLength({ min: 3, max: 30 }).withMessage('Tên phải từ 3-30 ký tự').trim().escape(),
  body('password').isLength({ min: 6 }).withMessage('Mật khẩu tối thiểu 6 ký tự'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { username, password, email } = req.body;
      const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
      if (exists) return res.status(409).json({ error: 'Tên người dùng hoặc email đã tồn tại' });

      const hash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
      const user = new User({ username, passwordHash: hash, email });
      await user.save();

      // create token
      const token = createToken({ id: user._id, username: user.username, role: user.role });
      res.cookie('sb_token', token, {
        httpOnly: true,
        sameSite: 'Strict',
        secure: COOKIE_SECURE,
        maxAge: 1000 * 60 * 60 // 1 hour (match JWT_EXPIRES_IN)
      });
      res.json({ ok: true, user: { username: user.username, wallet: user.wallet } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Login
router.post('/login',
  body('username').notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { username, password } = req.body;
      const user = await User.findOne({ username });
      if (!user) return res.status(401).json({ error: 'Người dùng hoặc mật khẩu không đúng' });

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return res.status(401).json({ error: 'Người dùng hoặc mật khẩu không đúng' });

      const token = createToken({ id: user._id, username: user.username, role: user.role });
      res.cookie('sb_token', token, {
        httpOnly: true,
        sameSite: 'Strict',
        secure: COOKIE_SECURE,
        maxAge: 1000 * 60 * 60
      });
      res.json({ ok: true, user: { username: user.username, wallet: user.wallet } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('sb_token', { httpOnly: true, sameSite: 'Strict', secure: COOKIE_SECURE });
  res.json({ ok: true });
});

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const token = req.cookies?.sb_token || req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Không có token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
  }
}

// Example protected route to get current user info
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('username wallet role createdAt').lean();
    if (!user) return res.status(404).json({ error: 'Người dùng không tồn tại' });
    res.json({ ok: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint to deposit (protected) - simple example
router.post('/deposit', authMiddleware, body('amount').isInt({ min: 1 }), async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.wallet = (user.wallet || 0) + Number(amount);
    await user.save();
    res.json({ ok: true, wallet: user.wallet });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
