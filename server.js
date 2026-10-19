'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const dns = require('node:dns');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { MongoClient, ObjectId } = require('mongodb');

const scrypt = promisify(crypto.scrypt);
const ROOT = __dirname;

// Load local development settings from .env while preserving values already set by the host.
function loadLocalEnvironment() {
  const envPath = path.join(ROOT, '.env');
  let contents;
  try { contents = fs.readFileSync(envPath, 'utf8').replace(/^\uFEFF/, ''); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  for (const line of contents.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || process.env[match[1]]) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")) || (value.startsWith('`') && value.endsWith('`'))) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
    } else {
      value = value.replace(/\s+#.*$/, '').trim();
    }
    process.env[match[1]] = value;
  }
}
loadLocalEnvironment();
if (process.env.MONGODB_DNS_SERVERS) {
  const servers = process.env.MONGODB_DNS_SERVERS.split(',').map(value => value.trim()).filter(Boolean);
  if (servers.length) dns.setServers(servers);
}

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const MAX_BODY_BYTES = 1024 * 1024;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ALLOWED_STATUSES = ['submitted', 'reviewing', 'approved', 'rejected', 'completed'];
let client;
let db;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.ico': 'image/x-icon', '.webp': 'image/webp', '.mp4': 'video/mp4', '.woff2': 'font/woff2'
};

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Request body is too large.'), { status: 413 }));
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (size === 0) return resolve({});
      if (!String(req.headers['content-type'] || '').includes('application/json')) return reject(Object.assign(new Error('Content-Type must be application/json.'), { status: 415 }));
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error();
        resolve(body);
      } catch { reject(Object.assign(new Error('Request body must be a valid JSON object.'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function text(value, max = 2000) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}
function emailValid(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function required(body, limits) {
  const fields = {};
  for (const [key, max] of Object.entries(limits)) {
    if (typeof body[key] !== 'string' || !body[key].trim()) fields[key] = 'This field is required.';
    else if (body[key].trim().length > max) fields[key] = `Must be ${max} characters or fewer.`;
  }
  return fields;
}
function publicUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email, role: user.role, createdAt: user.createdAt };
}
function storedBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value && Buffer.isBuffer(value.buffer)) return value.buffer.subarray(0, value.position || value.buffer.length);
  if (value && typeof value.value === 'function') return Buffer.from(value.value(true));
  return Buffer.from(value);
}
function tokenFrom(req) {
  const match = /^Bearer\s+([a-f0-9]{64})$/i.exec(req.headers.authorization || '');
  return match ? match[1] : null;
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
async function issueSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.collection('sessions').insertOne({ tokenHash: tokenHash(token), userId: user._id, createdAt: new Date(), expiresAt });
  return token;
}
async function currentUser(req) {
  const token = tokenFrom(req);
  if (!token) return null;
  const session = await db.collection('sessions').findOne({ tokenHash: tokenHash(token), expiresAt: { $gt: new Date() } });
  if (!session) return null;
  return db.collection('users').findOne({ _id: session.userId });
}
async function requireAdmin(req, res) {
  const user = await currentUser(req);
  if (!user) { json(res, 401, { error: 'Authentication required.' }); return null; }
  if (!['admin', 'staff'].includes(user.role)) { json(res, 403, { error: 'Team access required.' }); return null; }
  return user;
}
function objectId(value) { return ObjectId.isValid(value) && String(new ObjectId(value)) === value ? new ObjectId(value) : null; }
function queryLimit(url, fallback = 100) {
  const n = Number(url.searchParams.get('limit'));
  return Number.isInteger(n) ? Math.max(1, Math.min(n, 200)) : fallback;
}

async function bootstrapAdmin() {
  const email = text(process.env.ADMIN_EMAIL, 254).toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  const name = text(process.env.ADMIN_NAME || 'Administrator', 100);
  if (!email && !password) return;
  if (!emailValid(email) || typeof password !== 'string' || password.length < 10) {
    throw new Error('Set both ADMIN_EMAIL and ADMIN_PASSWORD; the admin password must be at least 10 characters.');
  }
  const users = db.collection('users');
  const salt = crypto.randomBytes(16);
  const passwordHash = await scrypt(password, salt, 64);
  await users.updateOne({ email }, {
    $set: { name, email, role: 'admin', passwordHash, salt, updatedAt: new Date() },
    $setOnInsert: { createdAt: new Date() }
  }, { upsert: true });
}

async function handleApi(req, res, url) {
  const users = db.collection('users');
  const requests = db.collection('managementRequests');
  const contacts = db.collection('contactMessages');
  const businesses = db.collection('businesses');

  if (req.method === 'GET' && url.pathname === '/api/health') {
    await db.command({ ping: 1 });
    return json(res, 200, { status: 'ok', storage: 'mongodb', timestamp: new Date().toISOString() });
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/signup') {
    const body = await readJson(req);
    const fields = required(body, { name: 100, email: 254, password: 128 });
    const normalizedEmail = text(body.email, 254).toLowerCase();
    if (!fields.email && !emailValid(normalizedEmail)) fields.email = 'Enter a valid email address.';
    if (!fields.password && body.password.length < 8) fields.password = 'Password must be at least 8 characters.';
    if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
    const salt = crypto.randomBytes(16);
    const passwordHash = await scrypt(body.password, salt, 64);
    const user = { name: text(body.name, 100), email: normalizedEmail, role: 'customer', salt, passwordHash, createdAt: new Date() };
    try { const result = await users.insertOne(user); user._id = result.insertedId; }
    catch (error) { if (error.code === 11000) return json(res, 409, { error: 'An account with this email already exists.' }); throw error; }
    return json(res, 201, { user: publicUser(user), token: await issueSession(user) });
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/signin') {
    const body = await readJson(req);
    if (!emailValid(body.email) || typeof body.password !== 'string' || body.password.length > 128) return json(res, 400, { error: 'A valid email and password are required.' });
    const user = await users.findOne({ email: body.email.trim().toLowerCase() });
    if (!user) return json(res, 401, { error: 'Email or password is incorrect.' });
    const candidate = await scrypt(body.password, storedBuffer(user.salt), 64);
    const savedHash = storedBuffer(user.passwordHash);
    if (candidate.length !== savedHash.length || !crypto.timingSafeEqual(candidate, savedHash)) return json(res, 401, { error: 'Email or password is incorrect.' });
    return json(res, 200, { user: publicUser(user), token: await issueSession(user) });
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/signout') {
    const token = tokenFrom(req);
    if (token) await db.collection('sessions').deleteOne({ tokenHash: tokenHash(token) });
    return json(res, 200, { message: 'Signed out.' });
  }

  if (req.method === 'GET' && url.pathname === '/api/auth/me') {
    const user = await currentUser(req);
    if (!user) return json(res, 401, { error: 'Authentication required.' });
    return json(res, 200, { user: publicUser(user) });
  }

  if (req.method === 'POST' && url.pathname === '/api/contact') {
    const body = await readJson(req);
    const fields = required(body, { firstName: 100, lastName: 100, email: 254, company: 200, inquiryType: 40, message: 5000 });
    if (!fields.email && !emailValid(body.email)) fields.email = 'Enter a valid email address.';
    if (body.privacy !== true) fields.privacy = 'Privacy consent is required.';
    if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
    const item = {
      firstName: text(body.firstName, 100), lastName: text(body.lastName, 100), email: text(body.email, 254).toLowerCase(),
      phone: text(body.phone, 40), company: text(body.company, 200), inquiryType: text(body.inquiryType, 40), message: text(body.message, 5000),
      budget: text(body.budget, 40), newsletter: body.newsletter === true, status: 'new', createdAt: new Date()
    };
    const result = await contacts.insertOne(item);
    return json(res, 201, { message: 'Your message was received.', id: result.insertedId.toString() });
  }

  if (req.method === 'POST' && url.pathname === '/api/requests') {
    const user = await currentUser(req);
    if (!user) return json(res, 401, { error: 'Sign in before submitting a management request.' });
    const body = await readJson(req);
    const fields = required(body, { companyName: 200, businessType: 50, industry: 50, companySize: 30, contactName: 150, position: 100, email: 254, phone: 40, serviceType: 60, challenges: 5000, objectives: 5000, priority: 20 });
    if (!fields.email && (!emailValid(body.email) || body.email.trim().toLowerCase() !== user.email)) fields.email = 'Use the email address on your account.';
    if (!['low', 'medium', 'high'].includes(body.priority)) fields.priority = 'Select low, medium, or high priority.';
    if (!['full-management', 'financial-management', 'operations-management', 'strategic-consulting'].includes(body.serviceType)) fields.serviceType = 'Select a valid management service.';
    if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
    const item = {
      userId: user._id, companyName: text(body.companyName, 200), businessType: text(body.businessType, 50), industry: text(body.industry, 50),
      companySize: text(body.companySize, 30), contactName: text(body.contactName, 150), position: text(body.position, 100), email: user.email,
      phone: text(body.phone, 40), serviceType: body.serviceType, challenges: text(body.challenges, 5000), objectives: text(body.objectives, 5000),
      requirements: text(body.requirements, 5000), priority: body.priority, startDate: text(body.startDate, 10), budgetRange: text(body.budgetRange, 30),
      uploadedFiles: Array.isArray(body.uploadedFiles) ? body.uploadedFiles.filter(x => typeof x === 'string').slice(0, 10).map(x => text(x, 255)) : [],
      status: 'submitted', createdAt: new Date(), updatedAt: new Date()
    };
    const result = await requests.insertOne(item);
    item._id = result.insertedId;
    return json(res, 201, { request: { ...item, id: result.insertedId.toString(), userId: user._id.toString() } });
  }

  if (req.method === 'GET' && url.pathname === '/api/requests') {
    const user = await currentUser(req);
    if (!user) return json(res, 401, { error: 'Authentication required.' });
    const items = await requests.find({ userId: user._id }).sort({ createdAt: -1 }).limit(queryLimit(url)).toArray();
    return json(res, 200, { requests: items.map(item => ({ ...item, id: item._id.toString(), userId: item.userId.toString() })) });
  }

  let match = /^\/api\/requests\/([a-f\d]{24})$/i.exec(url.pathname);
  if (req.method === 'GET' && match) {
    const user = await currentUser(req);
    if (!user) return json(res, 401, { error: 'Authentication required.' });
    const item = await requests.findOne({ _id: new ObjectId(match[1]), userId: user._id });
    if (!item) return json(res, 404, { error: 'Request not found.' });
    return json(res, 200, { request: { ...item, id: item._id.toString(), userId: item.userId.toString() } });
  }

  if (url.pathname.startsWith('/api/admin/')) {
    const admin = await requireAdmin(req, res);
    if (!admin) return;
    if (req.method === 'GET' && url.pathname === '/api/admin/overview') {
      const [requestCount, openCount, businessCount, contactCount, customerCount] = await Promise.all([
        requests.countDocuments(), requests.countDocuments({ status: { $in: ['submitted', 'reviewing'] } }), businesses.countDocuments(), contacts.countDocuments({ status: 'new' }), users.countDocuments({ role: 'customer' })
      ]);
      return json(res, 200, { requestCount, openCount, businessCount, newContactCount: contactCount, customerCount });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/team') {
      const members = await users.find({ role: { $in: ['admin', 'staff'] } }, { projection: { name: 1, email: 1, role: 1, createdAt: 1 } }).sort({ createdAt: 1 }).toArray();
      return json(res, 200, { members: members.map(publicUser) });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/team') {
      const body = await readJson(req);
      const fields = required(body, { name: 100, email: 254, password: 128 });
      const memberEmail = text(body.email, 254).toLowerCase();
      if (!fields.email && !emailValid(memberEmail)) fields.email = 'Enter a valid email address.';
      if (!fields.password && body.password.length < 12) fields.password = 'Team passwords must be at least 12 characters.';
      if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
      const salt = crypto.randomBytes(16);
      const passwordHash = await scrypt(body.password, salt, 64);
      const member = { name: text(body.name, 100), email: memberEmail, role: 'staff', salt, passwordHash, createdAt: new Date() };
      try { const result = await users.insertOne(member); member._id = result.insertedId; }
      catch (error) { if (error.code === 11000) return json(res, 409, { error: 'An account with this email already exists.' }); throw error; }
      return json(res, 201, { member: publicUser(member) });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/requests') {
      const filter = {};
      const status = url.searchParams.get('status');
      if (status && ALLOWED_STATUSES.includes(status)) filter.status = status;
      const items = await requests.find(filter).sort({ createdAt: -1 }).limit(queryLimit(url)).toArray();
      return json(res, 200, { requests: items.map(item => ({ ...item, id: item._id.toString(), userId: item.userId.toString() })) });
    }
    match = /^\/api\/admin\/requests\/([a-f\d]{24})$/i.exec(url.pathname);
    if (req.method === 'PATCH' && match) {
      const body = await readJson(req);
      const fields = {};
      if (body.status !== undefined) {
        if (!ALLOWED_STATUSES.includes(body.status)) fields.status = `Choose one of: ${ALLOWED_STATUSES.join(', ')}.`;
      }
      if (body.adminNotes !== undefined && (typeof body.adminNotes !== 'string' || body.adminNotes.length > 5000)) fields.adminNotes = 'Notes must be 5,000 characters or fewer.';
      if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
      const update = { updatedAt: new Date(), updatedBy: admin._id };
      if (body.status !== undefined) update.status = body.status;
      if (body.adminNotes !== undefined) update.adminNotes = text(body.adminNotes, 5000);
      const result = await requests.findOneAndUpdate({ _id: new ObjectId(match[1]) }, { $set: update }, { returnDocument: 'after' });
      if (!result) return json(res, 404, { error: 'Request not found.' });
      return json(res, 200, { request: { ...result, id: result._id.toString(), userId: result.userId.toString() } });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/businesses') {
      const items = await businesses.find({}).sort({ updatedAt: -1 }).limit(queryLimit(url)).toArray();
      return json(res, 200, { businesses: items.map(item => ({ ...item, id: item._id.toString(), requestId: item.requestId?.toString() || null })) });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/businesses') {
      const body = await readJson(req);
      const fields = required(body, { name: 200, industry: 100, contactName: 150, email: 254, status: 30 });
      if (!fields.email && !emailValid(body.email)) fields.email = 'Enter a valid email address.';
      if (!['active', 'onboarding', 'paused', 'completed'].includes(body.status)) fields.status = 'Choose active, onboarding, paused, or completed.';
      if (Object.keys(fields).length) return json(res, 400, { error: 'Validation failed.', fields });
      const item = {
        name: text(body.name, 200), industry: text(body.industry, 100), contactName: text(body.contactName, 150), email: text(body.email, 254).toLowerCase(),
        phone: text(body.phone, 40), status: body.status, serviceType: text(body.serviceType, 80), notes: text(body.notes, 5000),
        createdAt: new Date(), updatedAt: new Date(), updatedBy: admin._id
      };
      const linkedRequestId = objectId(body.requestId);
      if (body.requestId && !linkedRequestId) return json(res, 400, { error: 'Invalid management request ID.' });
      if (linkedRequestId) item.requestId = linkedRequestId;
      if (item.requestId) {
        const sourceRequest = await requests.findOne({ _id: item.requestId });
        if (!sourceRequest) return json(res, 400, { error: 'The linked management request was not found.' });
        if (sourceRequest.businessId) return json(res, 409, { error: 'A business record already exists for this request.' });
      }
      let result;
      try { result = await businesses.insertOne(item); }
      catch (error) { if (error.code === 11000) return json(res, 409, { error: 'A business record already exists for this request.' }); throw error; }
      if (item.requestId) await requests.updateOne({ _id: item.requestId, businessId: { $exists: false } }, { $set: { businessId: result.insertedId, updatedAt: new Date() } });
      item._id = result.insertedId;
      return json(res, 201, { business: { ...item, id: result.insertedId.toString(), requestId: item.requestId?.toString() || null } });
    }
    match = /^\/api\/admin\/businesses\/([a-f\d]{24})$/i.exec(url.pathname);
    if (req.method === 'PATCH' && match) {
      const body = await readJson(req);
      const update = { updatedAt: new Date(), updatedBy: admin._id };
      const limits = { name: 200, industry: 100, contactName: 150, phone: 40, serviceType: 80, notes: 5000 };
      for (const [key, limit] of Object.entries(limits)) if (body[key] !== undefined) {
        if (typeof body[key] !== 'string' || body[key].length > limit) return json(res, 400, { error: 'Validation failed.', fields: { [key]: `Must be text up to ${limit} characters.` } });
        update[key] = text(body[key], limit);
      }
      if (body.email !== undefined) {
        if (!emailValid(body.email)) return json(res, 400, { error: 'Validation failed.', fields: { email: 'Enter a valid email address.' } });
        update.email = text(body.email, 254).toLowerCase();
      }
      if (body.status !== undefined) {
        if (!['active', 'onboarding', 'paused', 'completed'].includes(body.status)) return json(res, 400, { error: 'Validation failed.', fields: { status: 'Choose active, onboarding, paused, or completed.' } });
        update.status = body.status;
      }
      const result = await businesses.findOneAndUpdate({ _id: new ObjectId(match[1]) }, { $set: update }, { returnDocument: 'after' });
      if (!result) return json(res, 404, { error: 'Business not found.' });
      return json(res, 200, { business: { ...result, id: result._id.toString(), requestId: result.requestId?.toString() || null } });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/contacts') {
      const items = await contacts.find({}).sort({ createdAt: -1 }).limit(queryLimit(url)).toArray();
      return json(res, 200, { contacts: items.map(item => ({ ...item, id: item._id.toString() })) });
    }
    if (req.method === 'PATCH' && /^\/api\/admin\/contacts\/[a-f\d]{24}$/i.test(url.pathname)) {
      const id = url.pathname.split('/').pop();
      const body = await readJson(req);
      if (!['new', 'read', 'replied', 'closed'].includes(body.status)) return json(res, 400, { error: 'Validation failed.', fields: { status: 'Choose new, read, replied, or closed.' } });
      const item = await contacts.findOneAndUpdate({ _id: new ObjectId(id) }, { $set: { status: body.status, updatedAt: new Date(), updatedBy: admin._id } }, { returnDocument: 'after' });
      if (!item) return json(res, 404, { error: 'Contact message not found.' });
      return json(res, 200, { contact: { ...item, id: item._id.toString() } });
    }
    return json(res, 404, { error: 'Admin API route not found.' });
  }

  return json(res, 404, { error: 'API route not found.' });
}

function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' });
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch { return json(res, 400, { error: 'Invalid URL path.' }); }
  if (pathname === '/') pathname = '/index.html';
  if (pathname.startsWith('/.') || pathname.includes('/../') || pathname.endsWith('/..')) return json(res, 404, { error: 'File not found.' });
  const filePath = path.resolve(ROOT, `.${pathname}`);
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) return json(res, 403, { error: 'Forbidden.' });
  if (!['.html', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.mp4', '.woff2', '.svg'].includes(path.extname(filePath).toLowerCase())) return json(res, 404, { error: 'File not found.' });
  fs.stat(filePath, (error, stats) => {
    if (error || !stats.isFile()) return json(res, 404, { error: 'File not found.' });
    res.writeHead(200, { 'Content-Type': MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream', 'Content-Length': stats.size, 'X-Content-Type-Options': 'nosniff' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(filePath).pipe(res);
  });
}

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing. Add it to the project .env file for local development, or to the service environment settings on Render.');
  client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  db = client.db(process.env.MONGODB_DATABASE || 'business_management');
  await Promise.all([
    db.collection('users').createIndex({ email: 1 }, { unique: true }),
    db.collection('sessions').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('managementRequests').createIndex({ userId: 1, createdAt: -1 }),
    db.collection('businesses').createIndex({ updatedAt: -1 }),
    db.collection('businesses').createIndex({ requestId: 1 }, { unique: true, sparse: true }),
    db.collection('contactMessages').createIndex({ createdAt: -1 })
  ]);
  await bootstrapAdmin();
  const server = http.createServer(async (req, res) => {
    let url;
    try { url = new URL(req.url, `http://${req.headers.host || 'localhost'}`); }
    catch { return json(res, 400, { error: 'Invalid request URL.' }); }
    try {
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      return serveStatic(req, res, url);
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      const status = Number.isInteger(error.status) ? error.status : 500;
      if (status === 500) console.error(error);
      return json(res, status, { error: status === 500 ? 'Internal server error.' : error.message });
    }
  });
  server.listen(PORT, HOST, () => console.log(`Business site and API listening on ${HOST}:${PORT}`));
  const shutdown = async () => {
    server.close(async () => { await client.close(); process.exit(0); });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch(async error => {
  console.error(`Startup failed: ${error.message}`);
  if (client) await client.close().catch(() => {});
  process.exit(1);
});
