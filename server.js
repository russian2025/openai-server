const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const allowedMacAddresses = ['D85ED35351D3', '60189512073D'];

let tokens = {};
const TOKEN_EXPIRY_TIME = 30 * 60 * 1000;

app.post('/checka', (req, res) => {
 const { aaa } = req.body;

 if (allowedMacAddresses.includes(aaa))
 {
  const token = generateToken(aaa);
  const expiry = Date.now() + TOKEN_EXPIRY_TIME;
  tokens[token] = { aaa, expiry };
  res.json({ success: true, token });
 }
 else  res.status(403).json({ error: 'Unauthorized...' });
});

function generateToken(aaa) { return Buffer.from(aaa + new Date().toISOString()).toString('base64'); }

app.post('/api/chat', async (req, res) => {
 const { messages, token } = req.body;

 if (!messages || !Array.isArray(messages) || !validateToken(token))
  return res.status(400).send({ error: "Invalid or expired token." });

 try {
  const response = await axios.post( 'https://api.openai.com/v1/chat/completions',
  {
   model: "gpt-3.5-turbo",
   messages: messages,
  },
  {
   headers:
   {
    Authorization: `Bearer ${API_KEY}`,
    "Content-Type": "application/json",
   }
  }
  );
  res.send(response.data);
 }
 catch (error) 
 {
  console.error("Error API:", error.message);
  res.status(500).send({ error: "Error with server or OpenAI API." });
 }
});

function validateToken(token) {
 const tokenData = tokens[token];
 if (!tokenData)  return false;
 if (Date.now() > tokenData.expiry)
 {
  delete tokens[token];
  return false;
 }
 return true;
}

app.listen(PORT, () => { console.log(`The server is running on port ${PORT}`); });
