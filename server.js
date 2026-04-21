const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/cramskey', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Machine Schema
const breakdownSchema = new mongoose.Schema({
  note: { type: String, required: true },
  images: [String],
  createdAt: { type: Date, default: Date.now },
});

const machineSchema = new mongoose.Schema({
  machineName: { type: String, required: true },
  machineNumber: { type: String, required: true, unique: true },
  machineType: { type: String, required: true },
  status: { type: String, enum: ['operational', 'breakdown', 'maintenance'], default: 'operational' },
  breakdowns: [breakdownSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Machine = mongoose.model('Machine', machineSchema);

// Multer config - max 5 images
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({
  storage,
  limits: { files: 5 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'), false);
  },
});

// Routes

// GET all machines
app.get('/api/machines', async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      query = {
        $or: [
          { machineName: { $regex: search, $options: 'i' } },
          { machineType: { $regex: search, $options: 'i' } },
          { machineNumber: { $regex: search, $options: 'i' } },
        ],
      };
    }
    const machines = await Machine.find(query).sort({ updatedAt: -1 });
    res.json(machines);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single machine
app.get('/api/machines/:id', async (req, res) => {
  try {
    const machine = await Machine.findById(req.params.id);
    if (!machine) return res.status(404).json({ error: 'Machine not found' });
    res.json(machine);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create machine
app.post('/api/machines', async (req, res) => {
  try {
    const machine = new Machine(req.body);
    await machine.save();
    res.status(201).json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// POST add breakdown report
app.post('/api/machines/:id/breakdown', upload.array('images', 5), async (req, res) => {
  try {
    const machine = await Machine.findById(req.params.id);
    if (!machine) return res.status(404).json({ error: 'Machine not found' });

    const imagePaths = req.files ? req.files.map(f => `/uploads/${f.filename}`) : [];

    machine.breakdowns.unshift({
      note: req.body.note,
      images: imagePaths,
      createdAt: new Date(),
    });
    machine.status = 'breakdown';
    machine.updatedAt = new Date();
    await machine.save();
    res.json(machine);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// PUT update machine status
app.put('/api/machines/:id/status', async (req, res) => {
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

// DELETE machine
app.delete('/api/machines/:id', async (req, res) => {
  try {
    await Machine.findByIdAndDelete(req.params.id);
    res.json({ message: 'Machine deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));