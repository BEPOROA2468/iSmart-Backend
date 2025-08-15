import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());

const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin: (o, cb)=> cb(null, !o || allowed.includes(o)),
  credentials: false
}));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE);

const BOT_TOKEN = process.env.BOT_TOKEN;
const SECRET_KEY = crypto.createHash('sha256').update(BOT_TOKEN).digest(); // Telegram data-check secret

// Verify Telegram WebApp initData (auth from client)
function verifyTelegramInitData(initData) {
  // initData is a URLSearchParams string from Telegram.WebApp.initData
  const parsed = Object.fromEntries(new URLSearchParams(initData));
  const { hash, ...data } = parsed;
  const dataCheckString = Object.keys(data)
    .sort()
    .map(k => ${k}=${data[k]})
    .join('\n');

  const hmac = crypto.createHmac('sha256', SECRET_KEY).update(dataCheckString).digest('hex');
  if (hmac !== hash) return null;

  // user is JSON string in initData
  const user = JSON.parse(data.user || '{}');
  return {
    id: String(user.id),
    name: [user.first_name, user.last_name].filter(Boolean).join(' ') || 'Guest',
    username: user.username ? '@' + user.username : '',
    email: ''
  };
}

// issue JWT for short-lived session
function sign(u) {
  return jwt.sign({ uid: u.id }, process.env.JWT_SECRET, { expiresIn: '2h' });
}
function auth(req, res, next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.uid = payload.uid;
    return next();
  } catch(e){ return res.status(401).json({error:'unauthorized'}); }
}

/* ===== Routes ===== */

// 1) Auth: client sends Telegram initData; server verifies & upserts user
app.post('/api/auth', async (req, res) => {
  const { initData } = req.body || {};
  if (!initData) return res.status(400).json({ error: 'missing initData' });

  const user = verifyTelegramInitData(initData);
  if (!user) return res.status(401).json({ error: 'bad signature' });

  await supabase.from('users').upsert({
    id: user.id, name: user.name, username: user.username, email: user.email
  }, { onConflict: 'id' });

  const { data } = await supabase.from('users').select('*').eq('id', user.id).single();
  return res.json({ token: sign(user), profile: data });
});

// 2) Get profile/balance
app.get('/api/me', auth, async (req, res) => {
  const { data, error } = await supabase.from('users').select('*').eq('id', req.uid).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// 3) Reward after ad (server-side cooldown)
app.post('/api/reward/ad', auth, async (req, res) => {
  const COOLDOWN = Number(process.env.COOLDOWN_SEC || 10);
  const REWARD = Number(process.env.REWARD_PER_AD || 10);

  const { data: user } = await supabase.from('users').select('*').eq('id', req.uid).single();
  const now = new Date();
  const last = user?.last_ad_at ? new Date(user.last_ad_at) : null;
  if (last && (now - last) / 1000 < COOLDOWN) {
    const left = Math.ceil(COOLDOWN - (now - last)/1000);
    return res.status(429).json({ error: 'cooldown', left });
  }

  const { error: uerr } = await supabase.from('users')
    .update({ balance: (user.balance || 0) + REWARD, last_ad_at: now.toISOString() })
    .eq('id', req.uid);
  if (uerr) return res.status(500).json({ error: uerr.message });

  await supabase.from('ad_events').insert({ user_id: req.uid, reward: REWARD });

  const { data: updated } = await supabase.from('users').select('*').eq('id', req.uid).single();
  res.json({ balance: updated.balance, last_ad_at: updated.last_ad_at });
});// 4) Withdraw request (coins)
app.post('/api/withdraw', auth, async (req, res) => {
  const { method, account, amount_coins } = req.body || {};
  if (!method  !account  !amount_coins) return res.status(400).json({ error: 'missing fields' });

  const COINS_PER_USDT = Number(process.env.COINS_PER_USDT || 100);
  const MIN_USDT = Number(process.env.MIN_WITHDRAW_USDT || 20);
  const minCoins = COINS_PER_USDT * MIN_USDT;

  const { data: user } = await supabase.from('users').select('*').eq('id', req.uid).single();
  if ((amount_coins|0) < minCoins) return res.status(400).json({ error: min ${minCoins} coins });
  if ((user.balance||0) < amount_coins) return res.status(400).json({ error: 'insufficient balance' });

  await supabase.from('withdraw_requests').insert({
    user_id: req.uid, method, account, amount_coins
  });
  await supabase.from('users').update({ balance: user.balance - amount_coins }).eq('id', req.uid);

  res.json({ ok: true });
});

// 5) Admin approve/reject (simple)
app.post('/api/admin/withdraw/:id/:action', async (req, res) => {
  const adminIds = (process.env.ADMIN_IDS||'').split(',').map(s=>s.trim());
  const { admin } = req.query; // pass ?admin=<telegram_id> for quick check
  if (!adminIds.includes(String(admin))) return res.status(403).json({error:'forbidden'});

  const { id, action } = req.params; // action: approve|reject
  if (!['approve','reject'].includes(action)) return res.status(400).json({error:'bad action'});

  await supabase.from('withdraw_requests').update({ status: action }).eq('id', id);
  res.json({ ok: true });
});

app.get('/', (_,res)=>res.send('OK'));
app.listen(process.env.PORT || 8080, ()=>console.log('Server up'));