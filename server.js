require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();

// ================== MIDDLEWARE ==================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ================== SCHEMAS ==================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin','donor','charity'], required: true },
  phone: String,
  address: String,
  certificate: String
});

const donationSchema = new mongoose.Schema({
  donorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  donorName: String,
  charityId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  charityName: { type: String, default: '' },
  items: String,
  quantity: Number,
  unit: String,
  expiryDate: Date,
  status: { type: String, enum: ['Donated','Requested','Accepted','Rejected'], default: 'Requested' },
  reason: String
});

const User = mongoose.model('User', userSchema);
const Donation = mongoose.model('Donation', donationSchema);

// ================== DATABASE ==================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ================== AUTH MIDDLEWARE ==================
function checkAuth(req,res,next){
  if(!req.session.userId) return res.status(401).json({ success:false, message:'Unauthorized' });
  next();
}

function checkRole(role){
  return (req,res,next)=>{
    if (req.session.role !== role) return res.status(403).json({ success:false, message:'Forbidden' });
    next();
  }
}

// ================== AUTH ROUTES ==================
app.post('/api/auth/register', async (req,res)=>{
  try{
    const { name,email,password,role,phone,address,certificate } = req.body;
    if(!name || !email || !password || !role) 
      return res.status(400).json({ success:false, message:'Missing required fields' });

    if(await User.findOne({ email })) return res.json({ success:false, message:'Email exists' });

    const hashed = await bcrypt.hash(password,10);
    await User.create({ name,email,password:hashed,role,phone,address,certificate });
    res.json({ success:true });
  } catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

app.post('/api/auth/login', async (req,res)=>{
  try{
    const { email,password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.json({ success:false, message:'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.json({ success:false, message:'Incorrect password' });

    req.session.userId = user._id.toString();
    req.session.role = user.role;
    req.session.name = user.name;
    res.json({ success:true, role:user.role });
  } catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

app.get('/api/auth/me', checkAuth, async (req,res)=>{
  const user = await User.findById(req.session.userId).select('-password');
  res.json(user);
});

app.get('/logout', (req,res)=> req.session.destroy(()=> res.redirect('/login.html')));

// ================== USER ROUTES ==================
app.put('/api/users/:id', checkAuth, async (req,res)=>{
  try{
    const { name,email,phone,address,certificate,currentPassword,newPassword } = req.body;
    if(!name || !email) return res.status(400).json({ success:false, message:'Name and email required' });

    const user = await User.findById(req.params.id);
    if(!user) return res.status(404).json({ success:false, message:'User not found' });

    // Password change
    if(currentPassword || newPassword){
      if(!currentPassword || !newPassword) return res.status(400).json({ success:false, message:'Current and new password required' });
      const match = await bcrypt.compare(currentPassword, user.password);
      if(!match) return res.status(400).json({ success:false, message:'Incorrect current password' });
      user.password = await bcrypt.hash(newPassword,10);
    }

    // Update fields
    user.name = name;
    user.email = email;
    user.phone = phone;
    user.address = address;
    user.certificate = certificate;

    await user.save();
    res.json({ success:true, user });
  } catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

const userFields = 'name email phone address certificate role';

app.get('/api/admins', checkAuth, checkRole('admin'), async (req,res)=>{
  res.json(await User.find({ role:'admin' }, userFields));
});

app.get('/api/donors', checkAuth, checkRole('admin'), async (req,res)=>{
  res.json(await User.find({ role:'donor' }, userFields));
});

app.get('/api/charities', checkAuth, async (req,res)=>{
  if(req.session.role==='admin'){
    res.json(await User.find({ role:'charity' }, userFields));
  } else {
    res.json(await User.find({ role:'charity' }, 'name address certificate'));
  }
});

app.get('/api/charities/:id', checkAuth, async (req,res)=>{
  const charity = await User.findById(req.params.id);
  res.json(charity);
});

app.delete('/api/users/:id', checkAuth, checkRole('admin'), async (req,res)=>{
  try{
    if(!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success:false, message:'Invalid user ID' });
    const user = await User.findByIdAndDelete(req.params.id);
    if(!user) return res.status(404).json({ success:false, message:'User not found' });
    res.json({ success:true, message:'User deleted successfully' });
  } catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

// ================== DONATION ROUTES ==================
app.get('/api/donations', checkAuth, async (req,res)=>{
  try{
    let donations = [];
    if(req.session.role === 'admin'){
      donations = await Donation.find()
        .populate('donorId', 'name')
        .populate('charityId', 'name')
        .sort({_id:-1});
    } else if(req.session.role === 'charity'){
      donations = await Donation.find({
        $or:[
          { status:'Donated' },
          { charityId: req.session.userId }
        ]
      })
      .populate('donorId', 'name')
      .populate('charityId', 'name')
      .sort({_id:-1});
    }
    res.json(donations);
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to fetch donations' });
  }
});

app.get('/api/my-donations', checkAuth, checkRole('donor'), async (req,res)=>{
  try{
    const donations = await Donation.find({ donorId: req.session.userId })
      .populate('charityId', 'name')
      .sort({_id:-1});
    res.json(donations);
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to fetch donations' });
  }
});

app.post('/api/donations', checkAuth, checkRole('donor'), async (req,res)=>{
  try{
    const { donorId, donorName, charityId, charityName, items, quantity, unit, expiryDate } = req.body;
    if(!donorId || !items || !quantity || !unit || !expiryDate)
      return res.status(400).json({ success:false, message:'All fields except charity are required' });

    const donationStatus = charityId ? 'Requested' : 'Donated';

    const donation = await Donation.create({
      donorId, donorName, charityId: charityId||null, charityName: charityName||'',
      items, quantity, unit, expiryDate: new Date(expiryDate), status: donationStatus
    });

    res.json({ success:true, donation });
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to create donation' });
  }
});

app.post('/api/donations/:id/request', checkAuth, checkRole('charity'), async (req,res)=>{
  try{
    const donation = await Donation.findById(req.params.id);
    if(!donation) return res.status(404).json({ success:false, message:'Donation not found' });

    donation.charityId = req.session.userId;
    donation.charityName = req.session.name;
    donation.status = 'Requested';
    await donation.save();

    res.json({ success:true });
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to request donation' });
  }
});

app.post('/api/donations/:id/accept', checkAuth, checkRole('admin'), async (req,res)=>{
  try{
    const donation = await Donation.findById(req.params.id);
    if(!donation) return res.status(404).json({ success:false, message:'Donation not found' });

    donation.status = 'Accepted';
    donation.reason = '';
    await donation.save();
    res.json({ success:true });
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to update donation' });
  }
});

app.post('/api/donations/:id/reject', checkAuth, checkRole('admin'), async (req,res)=>{
  try{
    const { reason } = req.body;
    if(!reason) return res.status(400).json({ success:false, message:'Reason required' });

    const donation = await Donation.findById(req.params.id);
    if(!donation) return res.status(404).json({ success:false, message:'Donation not found' });

    donation.status = 'Rejected';
    donation.reason = reason;
    await donation.save();
    res.json({ success:true });
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to update donation' });
  }
});

app.post('/api/donations/:id/reset', checkAuth, checkRole('admin'), async (req,res)=>{
  try{
    const donation = await Donation.findById(req.params.id);
    if(!donation) return res.status(404).json({ success:false, message:'Donation not found' });

    donation.status = 'Requested';
    donation.reason = '';
    await donation.save();
    res.json({ success:true });
  } catch(err){
    res.status(500).json({ success:false, message:'Failed to reset donation' });
  }
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
