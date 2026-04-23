require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();

app.use(express.json());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://kramskey-frontend.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'cramskey_secret_key_change_in_production';

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error('MongoDB error:', err));

/* ========================
   SCHEMAS
======================== */

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  companyId: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ['mechanic', 'lead_mechanic'],
    default: 'mechanic'
  },
  profilePicture: { type: String, default: '' },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const breakdownSchema = new mongoose.Schema({
  note: String,
  images: [String],
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  addedByName: String,
  createdAt: { type: Date, default: Date.now }
});

const machineSchema = new mongoose.Schema({
  machineName: { type: String, required: true },
  machineNumber: { type: String, required: true, unique: true },
  machineType: { type: String, required: true },
  status: {
    type: String,
    enum: ['operational', 'breakdown', 'maintenance'],
    default: 'operational'
  },
  breakdowns: [breakdownSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Machine = mongoose.model('Machine', machineSchema);

/* ========================
   MULTER
======================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  limits: { files: 5 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'));
  }
});

/* ========================
   MIDDLEWARE
======================== */
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const requireLeadMechanic = (req, res, next) => {
  if (req.user.role !== 'lead_mechanic') {
    return res.status(403).json({ error: 'Only Lead Mechanic can perform this action' });
  }
  next();
};

/* ========================
   AUTH ROUTES
======================== */

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, companyId, email, password } = req.body;

    if (!fullName || !companyId || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);

    // First user becomes lead_mechanic automatically
    const count = await User.countDocuments();
    const role = count === 0 ? 'lead_mechanic' : 'mechanic';

    const user = new User({ fullName, companyId, email, password: hashed, role });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        companyId: user.companyId,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// SIGNIN
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        companyId: user.companyId,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// FORGOT PASSWORD
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ error: 'No account with that email' });

    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${token}`;

    await transporter.sendMail({
      to: user.email,
      from: process.env.EMAIL_USER,
      subject: 'CRAMSKEY - Password Reset',
      html: `
        <h2>Password Reset Request</h2>
        <p>Hi ${user.fullName},</p>
        <p>You requested a password reset. Click the link below:</p>
        <a href="${resetUrl}" style="background:#f97316;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;">Reset Password</a>
        <p>This link expires in 1 hour.</p>
        <p>If you didn't request this, ignore this email.</p>
      `
    });

    res.json({ message: 'Password reset email sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send reset email. Check server email config.' });
  }
});

// RESET PASSWORD
app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ error: 'Invalid or expired reset token' });

    const { password } = req.body;
    if (!password || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GET current user
app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: req.user });
});

// UPLOAD AVATAR
app.post('/api/auth/upload-avatar', authenticate, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

    // Delete old profile picture file if it exists
    const existingUser = await User.findById(req.user._id);
    if (existingUser.profilePicture) {
      const oldPath = path.join(__dirname, existingUser.profilePicture);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    const avatarPath = `/uploads/${req.file.filename}`;
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { profilePicture: avatarPath },
      { new: true }
    ).select('-password');

    res.json({
      profilePicture: avatarPath,
      user: {
        _id: updatedUser._id,
        fullName: updatedUser.fullName,
        companyId: updatedUser.companyId,
        email: updatedUser.email,
        role: updatedUser.role,
        profilePicture: updatedUser.profilePicture
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ========================
   USER ROUTES
======================== */

// GET all users (authenticated)
app.get('/api/users', authenticate, async (req, res) => {
  try {
    const users = await User.find().select('-password -resetPasswordToken -resetPasswordExpires');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE user role (lead_mechanic only)
app.put('/api/users/:id/role', authenticate, requireLeadMechanic, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['mechanic', 'lead_mechanic'].includes(role))
      return res.status(400).json({ error: 'Invalid role' });

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select('-password');

    res.json(user);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ========================
   MACHINE ROUTES
======================== */

// GET all machines (authenticated)
app.get('/api/machines', authenticate, async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      query = {
        $or: [
          { machineName: { $regex: search, $options: 'i' } },
          { machineType: { $regex: search, $options: 'i' } },
          { machineNumber: { $regex: search, $options: 'i' } }
        ]
      };
    }
    const machines = await Machine.find(query).sort({ updatedAt: -1 });
    res.json(machines);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET machine by ID (authenticated)
app.get('/api/machines/:id', authenticate, async (req, res) => {
  try {
    const machine = await Machine.findById(req.params.id);
    if (!machine) return res.status(404).json({ error: 'Machine not found' });
    res.json(machine);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CREATE machine (lead_mechanic only)
app.post('/api/machines', authenticate, requireLeadMechanic, async (req, res) => {
  try {
    const machine = new Machine(req.body);
    await machine.save();
    res.status(201).json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ADD breakdown (any authenticated user)
app.post('/api/machines/:id/breakdown', authenticate, upload.array('images', 5), async (req, res) => {
  try {
    const machine = await Machine.findById(req.params.id);
    if (!machine) return res.status(404).json({ error: 'Machine not found' });

    const imagePaths = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];

    machine.breakdowns.unshift({
      note: req.body.note,
      images: imagePaths,
      addedBy: req.user._id,
      addedByName: req.user.fullName,
      createdAt: new Date()
    });

    machine.status = 'breakdown';
    machine.updatedAt = new Date();
    await machine.save();
    res.json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// UPDATE STATUS (lead_mechanic only)
app.put('/api/machines/:id/status', authenticate, requireLeadMechanic, async (req, res) => {
  try {
    const machine = await Machine.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status, updatedAt: new Date() },
      { new: true }
    );
    res.json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// DELETE MACHINE (lead_mechanic only)
app.delete('/api/machines/:id', authenticate, requireLeadMechanic, async (req, res) => {
  try {
    await Machine.findByIdAndDelete(req.params.id);
    res.json({ message: 'Machine deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE MACHINE details (lead_mechanic only)
app.put('/api/machines/:id', authenticate, requireLeadMechanic, async (req, res) => {
  try {
    const machine = await Machine.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
    res.json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});