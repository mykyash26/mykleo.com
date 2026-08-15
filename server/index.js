import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieSession from 'cookie-session';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { google } from 'googleapis';
import twilio from 'twilio';

const app = express();
const port = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || 'relay.db');
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, phone TEXT, phone_verified INTEGER DEFAULT 0, gmail_tokens TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);

app.set('trust proxy', 1);
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || true, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieSession({ name: 'relay', secret: process.env.SESSION_SECRET || 'change-me-in-production', httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }));

function requireEnv(...keys) { const missing = keys.filter(k => !process.env[k]); if (missing.length) throw new Error(`Missing environment variables: ${missing.join(', ')}`); }
function getUser(req) { return req.session?.userId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId) : null; }
function requireUser(req, res, next) { const user = getUser(req); if (!user) return res.status(401).json({ error: 'Not signed in' }); req.user = user; next(); }
function saveUser(email) {
  let user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user) { const r = db.prepare('INSERT INTO users(email) VALUES(?)').run(email); user = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid); }
  return user;
}
function encrypt(text) {
  requireEnv('APP_ENCRYPTION_KEY');
  const key = Buffer.from(process.env.APP_ENCRYPTION_KEY, 'hex');
  if (key.length !== 32) throw new Error('APP_ENCRYPTION_KEY must be 64 hex characters');
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), data.toString('hex')].join(':');
}
function decrypt(payload) {
  const [ivHex, tagHex, dataHex] = payload.split(':'); const key = Buffer.from(process.env.APP_ENCRYPTION_KEY, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex')); decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}

function googleClient() {
  requireEnv('GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','GOOGLE_REDIRECT_URI');
  return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
}

app.get('/health', (_req,res)=>res.json({ok:true, service:'relay-backend'}));
app.get('/api/me', (req,res)=>{ const u=getUser(req); res.json({ signedIn:!!u, user:u?{email:u.email,phone:u.phone,phoneVerified:!!u.phone_verified}:null, connected:{gmail:!!u?.gmail_tokens} }); });

app.get('/auth/gmail', (req,res)=>{
  try {
    const client=googleClient();
    const url=client.generateAuthUrl({access_type:'offline',prompt:'consent',scope:['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.send','openid','email']});
    res.redirect(url);
  } catch(e){ res.status(500).send(e.message); }
});

app.get('/auth/gmail/callback', async (req,res)=>{
  try {
    const client=googleClient(); const {tokens}=await client.getToken(req.query.code); client.setCredentials(tokens);
    const oauth=google.oauth2({version:'v2',auth:client}); const me=await oauth.userinfo.get(); const user=saveUser(me.data.email);
    db.prepare('UPDATE users SET gmail_tokens=? WHERE id=?').run(encrypt(JSON.stringify(tokens)),user.id); req.session.userId=user.id;
    res.redirect((process.env.FRONTEND_ORIGIN||'http://localhost:3000')+'/?connected=gmail');
  } catch(e){ res.status(500).send('Gmail connection failed. '+e.message); }
});

function decodeBody(data='') { return Buffer.from(data.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'); }
function header(headers,name){ return headers.find(h=>h.name.toLowerCase()===name.toLowerCase())?.value || ''; }
function gmailClientFor(user){ const c=googleClient(); c.setCredentials(JSON.parse(decrypt(user.gmail_tokens))); return google.gmail({version:'v1',auth:c}); }

app.get('/api/inbox', requireUser, async (req,res)=>{
  try {
    const results=[];
    if(req.user.gmail_tokens){
      const gmail=gmailClientFor(req.user); const list=await gmail.users.messages.list({userId:'me',maxResults:25,labelIds:['INBOX']});
      for(const item of (list.data.messages||[])){
        const m=await gmail.users.messages.get({userId:'me',id:item.id,format:'metadata',metadataHeaders:['From','To','Subject','Date']});
        const h=m.data.payload?.headers||[]; const from=header(h,'From');
        results.push({id:item.id,provider:'gmail',threadId:m.data.threadId,from,subject:header(h,'Subject')||'(no subject)',date:header(h,'Date'),snippet:m.data.snippet||'',unread:(m.data.labelIds||[]).includes('UNREAD')});
      }
    }
    res.json({messages:results});
  } catch(e){ res.status(500).json({error:'Could not load inbox',detail:e.message}); }
});

app.get('/api/thread/:id', requireUser, async (req,res)=>{
  try {
    if(req.query.provider!=='gmail' || !req.user.gmail_tokens) return res.status(400).json({error:'Unsupported provider'});
    const gmail=gmailClientFor(req.user); const thread=await gmail.users.threads.get({userId:'me',id:req.params.id,format:'full'});
    const messages=(thread.data.messages||[]).map(m=>{const h=m.payload?.headers||[]; return {id:m.id,from:header(h,'From'),to:header(h,'To'),subject:header(h,'Subject'),date:header(h,'Date'),text:m.snippet||''};});
    res.json({messages});
  } catch(e){res.status(500).json({error:'Could not load conversation',detail:e.message});}
});

app.post('/api/reply', requireUser, async (req,res)=>{
  try {
    const {provider,threadId,to,subject,text}=req.body||{}; if(!text?.trim()) return res.status(400).json({error:'Message is empty'});
    if(provider!=='gmail' || !req.user.gmail_tokens) return res.status(400).json({error:'Only connected Gmail is enabled for replies right now'});
    const gmail=gmailClientFor(req.user);
    const raw=[`To: ${to}`,`Subject: ${subject||''}`,'Content-Type: text/plain; charset=utf-8','',text.trim()].join('\r\n');
    const encoded=Buffer.from(raw).toString('base64url');
    await gmail.users.messages.send({userId:'me',requestBody:{raw:encoded,threadId}});
    res.json({ok:true});
  } catch(e){res.status(500).json({error:'Reply failed',detail:e.message});}
});

app.post('/api/phone/send', requireUser, async (req,res)=>{
  try { requireEnv('TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN','TWILIO_VERIFY_SERVICE_SID'); const phone=String(req.body.phone||'').trim(); if(!/^\+[1-9]\d{7,14}$/.test(phone)) return res.status(400).json({error:'Use international format, e.g. +15551234567'}); const client=twilio(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN); await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verifications.create({to:phone,channel:'sms'}); db.prepare('UPDATE users SET phone=? WHERE id=?').run(phone,req.user.id); res.json({ok:true}); } catch(e){res.status(500).json({error:'Could not send verification',detail:e.message});}
});
app.post('/api/phone/verify', requireUser, async (req,res)=>{
  try { requireEnv('TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN','TWILIO_VERIFY_SERVICE_SID'); const code=String(req.body.code||'').trim(); const client=twilio(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN); const r=await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verificationChecks.create({to:req.user.phone,code}); if(r.status!=='approved') return res.status(400).json({error:'Invalid verification code'}); db.prepare('UPDATE users SET phone_verified=1 WHERE id=?').run(req.user.id); res.json({ok:true}); } catch(e){res.status(500).json({error:'Verification failed',detail:e.message});}
});

app.post('/api/logout',(req,res)=>{req.session=null;res.json({ok:true});});
app.listen(port,()=>console.log(`Relay backend listening on :${port}`));
