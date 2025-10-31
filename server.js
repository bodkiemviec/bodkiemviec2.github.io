require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;

(async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connect error', err);
    process.exit(1);
  }

  const app = express();

  // Security middlewares
  app.use(helmet());
  app.use(express.json());
  app.use(cookieParser());

  // CORS - allow only front-end origin
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5500';
  app.use(cors({
    origin: corsOrigin,
    credentials: true
  }));

  // Rate limiter (apply to auth endpoints)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
  });
  app.use('/api/auth', authLimiter);

  // Routes
  app.use('/api/auth', authRoutes);

  // a protected test route
  app.get('/api/me', (req, res) => {
    res.json({ ok: true, msg: 'backend running' });
  });

  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();
