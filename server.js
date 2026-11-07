import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, DeleteCommand, UpdateCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

if (!process.env.AWS_REGION) { console.error('AWS_REGION missing'); process.exit(1); }
if (!process.env.TABLE_NAME) { console.error('TABLE_NAME missing'); process.exit(1); }
if (!process.env.BUCKET_NAME) { console.error('BUCKET_NAME missing'); process.exit(1); }
if (!process.env.COGNITO_CLIENT_ID) { console.error('COGNITO_CLIENT_ID missing'); process.exit(1); }

const db = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.AWS_REGION }));
const s3 = new S3Client({ region: process.env.AWS_REGION });
const idp = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
const TABLE = process.env.TABLE_NAME;
const BUCKET = process.env.BUCKET_NAME;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function parseCookie(header) {
  const cookies = {};
  String(header || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k] = v.join('=');
  });
  return cookies;
}

async function requireUser(req, res, next) {
  const cookies = parseCookie(req.headers.cookie);
  const token = cookies.at;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { UserAttributes } = await idp.send(new GetUserCommand({ AccessToken: token }));
    const attrs = Object.fromEntries(UserAttributes.map(a => [a.Name, a.Value]));
    req.user = { sub: attrs.sub, email: attrs.email };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/health', (_, res) => res.send('ok'));

app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    await idp.send(new SignUpCommand({
      ClientId: CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: 'email', Value: email }]
    }));
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/auth/confirm', async (req, res) => {
  try {
    const { email, code } = req.body;
    await idp.send(new ConfirmSignUpCommand({ ClientId: CLIENT_ID, Username: email, ConfirmationCode: code }));
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await idp.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password }
    }));
    if (!result.AuthenticationResult) return res.status(400).json({ error: 'Auth failed' });
    res.setHeader('Set-Cookie', 'at=' + result.AuthenticationResult.AccessToken + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=3300');
    res.json({ ok: true });
  } catch (e) {
    if (e.name === 'UserNotConfirmedException') return res.status(403).json({ code: 'NOT_CONFIRMED', error: e.message });
    res.status(400).json({ error: e.message });
  }
});

app.post('/auth/logout', (_, res) => {
  res.setHeader('Set-Cookie', 'at=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/auth/me', async (req, res) => {
  const cookies = parseCookie(req.headers.cookie);
  const token = cookies.at;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { UserAttributes } = await idp.send(new GetUserCommand({ AccessToken: token }));
    const attrs = Object.fromEntries(UserAttributes.map(a => [a.Name, a.Value]));
    res.json({ email: attrs.email });
  } catch { res.status(401).json({ error: 'Invalid token' }); }
});

function userPk(sub) { return 'USER#' + sub; }

app.get('/api/products', async (_, res) => {
  try {
    const { Items } = await db.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': 'PRODUCTS' }
    }));
    res.json(Items || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const { Item } = await db.send(new GetCommand({
      TableName: TABLE,
      Key: { pk: 'PRODUCTS', sk: 'PRODUCT#' + req.params.id }
    }));
    if (!Item) return res.status(404).json({ error: 'Not found' });
    res.json(Item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products', requireUser, async (req, res) => {
  try {
    const { name, description, price, category, imageKey } = req.body;
    const id = randomUUID();
    const item = {
      pk: 'PRODUCTS',
      sk: 'PRODUCT#' + id,
      id,
      name,
      description,
      price: Number(price),
      category,
      imageKey: imageKey || null,
      createdAt: new Date().toISOString()
    };
    await db.send(new PutCommand({ TableName: TABLE, Item: item }));
    res.status(201).json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', requireUser, async (req, res) => {
  try {
    await db.send(new DeleteCommand({
      TableName: TABLE,
      Key: { pk: 'PRODUCTS', sk: 'PRODUCT#' + req.params.id }
    }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/cart', requireUser, async (req, res) => {
  try {
    const { Items } = await db.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': userPk(req.user.sub) + '#CART' }
    }));
    res.json(Items || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cart', requireUser, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    const pk = userPk(req.user.sub) + '#CART';
    const sk = 'ITEM#' + productId;
    const existing = await db.send(new GetCommand({ TableName: TABLE, Key: { pk, sk } }));
    const qty = (existing.Item?.quantity || 0) + (quantity || 1);
    await db.send(new PutCommand({
      TableName: TABLE,
      Item: { pk, sk, productId, quantity: qty, updatedAt: new Date().toISOString() }
    }));
    res.json({ ok: true, quantity: qty });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/cart/:productId', requireUser, async (req, res) => {
  try {
    const { quantity } = req.body;
    const pk = userPk(req.user.sub) + '#CART';
    const sk = 'ITEM#' + req.params.productId;
    if (quantity <= 0) {
      await db.send(new DeleteCommand({ TableName: TABLE, Key: { pk, sk } }));
    } else {
      await db.send(new UpdateCommand({
        TableName: TABLE,
        Key: { pk, sk },
        UpdateExpression: 'SET quantity = :q, updatedAt = :u',
        ExpressionAttributeValues: { ':q': quantity, ':u': new Date().toISOString() }
      }));
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/cart/:productId', requireUser, async (req, res) => {
  try {
    const pk = userPk(req.user.sub) + '#CART';
    const sk = 'ITEM#' + req.params.productId;
    await db.send(new DeleteCommand({ TableName: TABLE, Key: { pk, sk } }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders', requireUser, async (req, res) => {
  try {
    const { Items: cartItems } = await db.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': userPk(req.user.sub) + '#CART' }
    }));
    if (!cartItems?.length) return res.status(400).json({ error: 'Cart empty' });

    const productIds = cartItems.map(i => i.productId);
    const products = {};
    for (const pid of productIds) {
      const { Item } = await db.send(new GetCommand({
        TableName: TABLE,
        Key: { pk: 'PRODUCTS', sk: 'PRODUCT#' + pid }
      }));
      if (Item) products[pid] = Item;
    }

    let total = 0;
    const orderItems = cartItems.map(ci => {
      const p = products[ci.productId];
      const price = p?.price || 0;
      total += price * ci.quantity;
      return { productId: ci.productId, name: p?.name, price, quantity: ci.quantity, imageKey: p?.imageKey };
    });

    const orderId = randomUUID();
    const order = {
      pk: userPk(req.user.sub) + '#ORDERS',
      sk: 'ORDER#' + orderId,
      id: orderId,
      items: orderItems,
      total,
      status: 'confirmed',
      createdAt: new Date().toISOString()
    };
    await db.send(new PutCommand({ TableName: TABLE, Item: order }));

    for (const ci of cartItems) {
      await db.send(new DeleteCommand({
        TableName: TABLE,
        Key: { pk: userPk(req.user.sub) + '#CART', sk: 'ITEM#' + ci.productId }
      }));
    }

    res.status(201).json(order);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/orders', requireUser, async (req, res) => {
  try {
    const { Items } = await db.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': userPk(req.user.sub) + '#ORDERS' },
      ScanIndexForward: false
    }));
    res.json(Items || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/upload', express.raw({ type: () => true, limit: '10mb' }), async (req, res) => {
  try {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ error: 'Empty file' });
    const cookies = parseCookie(req.headers.cookie);
    const token = cookies.at;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const { UserAttributes } = await idp.send(new GetUserCommand({ AccessToken: token }));
    const attrs = Object.fromEntries(UserAttributes.map(a => [a.Name, a.Value]));
    const sub = attrs.sub;

    const safeName = String(req.query.name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100);
    const key = 'uploads/' + sub + '/' + randomUUID() + '-' + safeName;
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      Body: req.body,
      ContentType: req.headers['content-type'] || 'application/octet-stream'
    }));
    res.json({ key });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/download', async (req, res) => {
  try {
    const key = req.query.key;
    if (!key || !/^uploads\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(key)) return res.status(400).json({ error: 'Invalid key' });
    const { Body, ContentType } = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
    res.setHeader('Content-Type', ContentType || 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const inlineTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
    res.setHeader('Content-Disposition', inlineTypes.includes(ContentType) ? 'inline' : 'attachment');
    Body.pipe(res);
  } catch (e) {
    if (e.name === 'NoSuchKey') return res.status(404).json({ error: 'Not found' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/files', requireUser, async (req, res) => {
  try {
    const key = req.query.key;
    if (!key || !key.startsWith('uploads/' + req.user.sub + '/')) return res.status(400).json({ error: 'Invalid key' });
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(3000, '0.0.0.0', () => console.log('Server running on port 3000'));
