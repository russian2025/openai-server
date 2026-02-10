const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const ttsCache = new Map();                    // key → base64 mp3
const SIGN_SECRET = process.env.SIGN_SECRET || 'RCESYM6202TE';

const app = express();

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  console.error('❌ API_KEY is not set');
}

app.use(cors({
  origin: '*',                                 // при желании ограничим
  methods: ['POST', 'GET']
}));

app.use(express.json({ limit: '50kb' }));

app.set('trust proxy', 1);

app.use('/api/', rateLimit({                   // Rate limit для API 
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
}));

const allowedMacAddresses = ['D85ED35351D2', '60189512073D', '08606E944B0C'];

const TOKEN_EXPIRY_TIME = 30 * 60 * 1000;            // 30 минут
const tokens = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');     // 256-bit
}

function validateToken(token) {
  const data = tokens.get(token);
  if (!data) return false;

  if (Date.now() > data.expiry) {
    tokens.delete(token);
    return false;
  }
  return true;
}

app.get('/health', (_, res) => res.send('ok'));      // Health check

function verifySignedMac(mac, timestamp, signature) {
  if (!mac || !timestamp || !signature) return false;

                                    // timestamp должен быть свежим (±60 сек)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Math.abs(now - ts) > 60) return false;

  const expected = crypto
    .createHash('sha256')
    .update(mac + timestamp + SIGN_SECRET)
    .digest('hex');

  return crypto.timingSafeEqual(                     // timing-safe compare
    Buffer.from(expected),
    Buffer.from(signature)
  );
}

app.post('/checka', (req, res) => {                  // Получение токена
  const { aaa, t, s  } = req.body;

  if (!aaa || typeof aaa !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }

  if (!verifySignedMac(aaa, t, s)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }

  if (!allowedMacAddresses.includes(aaa)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const token = generateToken();

  tokens.set(token, {
    aaa,
    expiry: Date.now() + TOKEN_EXPIRY_TIME
  });

  res.json({
    success: true,
    token,
    expiresIn: TOKEN_EXPIRY_TIME / 1000
  });
});

app.post('/api/chat', async (req, res) => {              // Chat API
  const { messages, token } = req.body;

  if (!token || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  if (!validateToken(token, req)) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-3.5-turbo',
        messages
      },
      {
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    res.json(response.data);

  } catch (error) {
    console.error('OpenAI error:', error.response?.data || error.message);
    res.status(500).json({ error: 'OpenAI API error' });
  }
});

setInterval(() => {            // Очистка протухших токенов каждые 5 минут
  const now = Date.now();
  for (const [token, data] of tokens.entries()) {
    if (now > data.expiry) {
      tokens.delete(token);
    }
  }
}, 5 * 60 * 1000);

app.post('/api/tts', async (req, res) => {
  const { text, token, speed = 1.0 } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'No text' });
  }

  if (!validateToken(token)) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  const cacheKey = crypto                        // ключ кэша
    .createHash('sha256')
    .update(text + '|' + speed)
    .digest('hex');
                                      // если уже есть — отдаём сразу
  if (ttsCache.has(cacheKey)) {      
    return res.json({ audio: ttsCache.get(cacheKey), cached: true });
  }

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/audio/speech',
      {
        model: 'gpt-4o-mini-tts',
        voice: 'alloy',
        input: text,
        format: 'mp3',
        speed: speed                              // Скорость
      },
      {
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          'Content-Type': 'application/json'
        },
        responseType: 'arraybuffer',
        timeout: 20000
      }
    );

    const base64Audio =
      `data:audio/mp3;base64,${Buffer.from(response.data).toString('base64')}`;

    ttsCache.set(cacheKey, base64Audio);         // сохраняем в кэш

    res.json({ audio: base64Audio, cached: false });

  } catch (error) {
    console.error('TTS error:', error.response?.data || error.message);
    res.status(500).json({ error: 'TTS failed' });
  }
});

app.listen(PORT, () => {                                    // Start
  console.log(`Server running on port ${PORT}`);
});

