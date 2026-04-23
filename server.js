// ============================================================
// MIRASTORE BACKEND — Express + MongoDB API
// ============================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'mirastore_secret_change_in_production';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/mirastore';

// ---- Middleware ----
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create uploads dir if needed
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// ---- MongoDB Connection ----
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ---- Schemas ----
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  role: { type: String, enum: ['admin', 'vendor', 'buyer'], default: 'buyer' },
  phone: String,
  vendorId: String,
  mustChangePassword: { type: Boolean, default: false },
  joinedAt: { type: Date, default: Date.now }
});

const vendorSchema = new mongoose.Schema({
  name: String,
  owner: String,
  email: { type: String, unique: true, lowercase: true },
  phone: String,
  category: String,
  description: String,
  account: String,
  bank: String,
  status: { type: String, enum: ['active', 'suspended', 'pending'], default: 'pending' },
  plan: { type: String, enum: ['monthly', 'semi-annual', 'annual', 'none'], default: 'none' },
  planExpiry: Date,
  planFee: Number,
  planPaid: { type: Boolean, default: false },
  joined: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  name: String,
  price: Number,
  category: String,
  description: String,
  image: String,
  stock: { type: Number, default: 0 },
  rating: { type: Number, default: 0 },
  sales: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: [{ productId: String, qty: Number, price: Number }],
  total: Number,
  status: { type: String, enum: ['pending', 'processing', 'delivered', 'cancelled'], default: 'pending' },
  paymentStatus: { type: String, enum: ['unpaid', 'receipt_uploaded', 'paid'], default: 'unpaid' },
  buyer: String,
  phone: String,
  address: String,
  receiptUrl: String,
  txref: String,
  note: String,
  date: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  messages: [{
    senderId: String,
    senderName: String,
    text: String,
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
  }],
  lastActivity: { type: Date, default: Date.now }
});

const bargainSchema = new mongoose.Schema({
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  buyerName: String,
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  productName: String,
  originalPrice: Number,
  offeredPrice: Number,
  message: String,
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'countered'], default: 'pending' },
  vendorCounter: Number,
  vendorNote: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Vendor = mongoose.model('Vendor', vendorSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Bargain = mongoose.model('Bargain', bargainSchema);

// ---- Auth Middleware ----
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ---- File Upload ----
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ name, email, phone, password: hashed, role: 'buyer' });
    await user.save();
    res.status(201).json({ message: 'Account created successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, role: user.role, name: user.name, vendorId: user.vendorId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role, mustChangePassword: user.mustChangePassword } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect' });
    user.password = await bcrypt.hash(newPassword, 12);
    user.mustChangePassword = false;
    await user.save();
    res.json({ message: 'Password updated successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin force password change (for any user)
app.put('/api/admin/users/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.password = await bcrypt.hash(newPassword, 12);
    user.mustChangePassword = true;
    await user.save();
    res.json({ message: 'Password reset. User will be prompted to change on next login.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// VENDOR ROUTES
// ============================================================
app.get('/api/vendors', async (req, res) => {
  try {
    const vendors = await Vendor.find({ status: 'active' }).select('-account -bank');
    res.json(vendors);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/vendors/all', auth, adminOnly, async (req, res) => {
  try { res.json(await Vendor.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/vendors', auth, adminOnly, async (req, res) => {
  try {
    const vendor = new Vendor(req.body);
    await vendor.save();
    // Create user account for vendor
    const tempPw = await bcrypt.hash('CHANGE_ME_' + Date.now(), 12);
    const user = new User({ name: vendor.name, email: vendor.email, phone: vendor.phone, password: tempPw, role: 'vendor', vendorId: vendor._id.toString(), mustChangePassword: true });
    await user.save();
    res.status(201).json({ vendor, message: 'Vendor created. Share login credentials.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/vendors/:id', auth, adminOnly, async (req, res) => {
  try {
    const v = await Vendor.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(v);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// PRODUCT ROUTES
// ============================================================
app.get('/api/products', async (req, res) => {
  try {
    const { category, vendor, search } = req.query;
    let query = { isActive: true };
    if (category) query.category = category;
    if (vendor) query.vendorId = vendor;
    if (search) query.name = { $regex: search, $options: 'i' };
    const products = await Product.find(query).populate('vendorId', 'name category');
    res.json(products);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const p = await Product.findById(req.params.id).populate('vendorId', 'name description category phone email');
    if (!p) return res.status(404).json({ error: 'Product not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    if (req.user.role !== 'vendor' && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const product = new Product({ ...req.body, vendorId: req.user.vendorId || req.body.vendorId });
    await product.save();
    res.status(201).json(product);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/products/:id', auth, async (req, res) => {
  try {
    const p = await Product.findById(req.params.id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && p.vendorId.toString() !== req.user.vendorId) return res.status(403).json({ error: 'Forbidden' });
    Object.assign(p, req.body);
    await p.save();
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/products/:id', auth, async (req, res) => {
  try {
    const p = await Product.findById(req.params.id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && p.vendorId.toString() !== req.user.vendorId) return res.status(403).json({ error: 'Forbidden' });
    if (p.sales > 0) return res.status(400).json({ error: 'Cannot delete product with sales history' });
    await p.deleteOne();
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Image upload for products
app.post('/api/upload', auth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const url = `${process.env.BACKEND_URL || 'http://localhost:5000'}/uploads/${req.file.filename}`;
  res.json({ url });
});

// ============================================================
// ORDER ROUTES
// ============================================================
app.get('/api/orders', auth, async (req, res) => {
  try {
    let orders;
    if (req.user.role === 'admin') {
      orders = await Order.find().sort({ date: -1 });
    } else if (req.user.role === 'buyer') {
      orders = await Order.find({ userId: req.user.id }).sort({ date: -1 });
    } else if (req.user.role === 'vendor') {
      // Vendor sees orders containing their products
      const vendorProducts = await Product.find({ vendorId: req.user.vendorId }).select('_id');
      const pIds = vendorProducts.map(p => p._id.toString());
      orders = await Order.find({ 'items.productId': { $in: pIds } }).sort({ date: -1 });
    }
    res.json(orders);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const order = new Order({ ...req.body, userId: req.user.id });
    await order.save();
    // Decrement stock
    for (const item of order.items) {
      await Product.findByIdAndUpdate(item.productId, { $inc: { stock: -item.qty, sales: item.qty } });
    }
    res.status(201).json(order);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/orders/:id/status', auth, async (req, res) => {
  try {
    const { status, paymentStatus } = req.body;
    const update = {};
    if (status) update.status = status;
    if (paymentStatus) update.paymentStatus = paymentStatus;
    const o = await Order.findByIdAndUpdate(req.params.id, update, { new: true });
    res.json(o);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// CHAT ROUTES (Vendor ↔ Buyer)
// ============================================================
app.get('/api/chats', auth, async (req, res) => {
  try {
    let chats;
    if (req.user.role === 'buyer') {
      chats = await Chat.find({ buyerId: req.user.id }).populate('vendorId', 'name').populate('productId', 'name image');
    } else if (req.user.role === 'vendor') {
      chats = await Chat.find({ vendorId: req.user.vendorId }).populate('buyerId', 'name').populate('productId', 'name image');
    } else {
      chats = await Chat.find().populate('buyerId', 'name').populate('vendorId', 'name').populate('productId', 'name');
    }
    res.json(chats);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chats', auth, async (req, res) => {
  try {
    const { vendorId, productId } = req.body;
    let thread = await Chat.findOne({ buyerId: req.user.id, vendorId, productId });
    if (!thread) {
      thread = new Chat({ buyerId: req.user.id, vendorId, productId });
      await thread.save();
    }
    res.json(thread);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chats/:id/message', auth, async (req, res) => {
  try {
    const { text } = req.body;
    const thread = await Chat.findById(req.params.id);
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    const msg = { senderId: req.user.id, senderName: req.user.name, text, timestamp: new Date() };
    thread.messages.push(msg);
    thread.lastActivity = new Date();
    await thread.save();
    res.json(msg);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// BARGAIN ROUTES
// ============================================================
app.get('/api/bargains', auth, async (req, res) => {
  try {
    let bargains;
    if (req.user.role === 'buyer') bargains = await Bargain.find({ buyerId: req.user.id }).sort({ createdAt: -1 });
    else if (req.user.role === 'vendor') bargains = await Bargain.find({ vendorId: req.user.vendorId }).sort({ createdAt: -1 });
    else bargains = await Bargain.find().sort({ createdAt: -1 });
    res.json(bargains);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/bargains', auth, async (req, res) => {
  try {
    if (req.user.role !== 'buyer') return res.status(403).json({ error: 'Only buyers can make bargain requests' });
    const existing = await Bargain.findOne({ buyerId: req.user.id, productId: req.body.productId, status: 'pending' });
    if (existing) return res.status(400).json({ error: 'You already have a pending offer on this product' });
    const bargain = new Bargain({ ...req.body, buyerId: req.user.id, buyerName: req.user.name });
    await bargain.save();
    res.status(201).json(bargain);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/bargains/:id/respond', auth, async (req, res) => {
  try {
    if (req.user.role !== 'vendor') return res.status(403).json({ error: 'Only vendors can respond to bargains' });
    const { status, vendorCounter, vendorNote } = req.body;
    const b = await Bargain.findByIdAndUpdate(req.params.id, { status, vendorCounter, vendorNote, updatedAt: new Date() }, { new: true });
    res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const [users, vendors, products, orders] = await Promise.all([
      User.countDocuments(),
      Vendor.countDocuments({ status: 'active' }),
      Product.countDocuments({ isActive: true }),
      Order.find()
    ]);
    const revenue = orders.filter(o => o.paymentStatus === 'paid').reduce((s, o) => s + o.total, 0);
    const pendingOrders = orders.filter(o => o.status === 'pending').length;
    res.json({ users, vendors, products, orders: orders.length, revenue, pendingOrders });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'OK', time: new Date() }));

app.listen(PORT, () => console.log(`🚀 Mirastore API running on port ${PORT}`));
