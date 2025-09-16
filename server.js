// =================================================================
// Dependencies
// =================================================================
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const path = require('path');

// =================================================================
// Initial Setup
// =================================================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// =================================================================
/* Database */
// =================================================================
mongoose.connect(MONGO_URI)
  .then(()=>console.log('MongoDB connected successfully.'))
  .catch(err=>console.error('MongoDB connection error:', err));

// =================================================================
/* Schemas & Models */
// =================================================================
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['Employee','Admin','IT','Cleaning','Canteen'], default: 'Employee' },
  employeeId: { type: String, required: true, unique: true },
  department: String,
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const chatMessageSchema = new mongoose.Schema({
  senderId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  senderName: String,
  senderRole: String,
  message:    String,
  timestamp:  { type: Date, default: Date.now },
});

const ticketSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  employeeName: String,
  department: String,
  floorNumber: String,
  tableNumber: String,
  mainIssue: String,
  problemDescription: String,
  status: { type: String, default: 'Pending' }, // Pending | In Progress | Resolved
  chatHistory: [chatMessageSchema],
  resolvedBy: String,
  resolutionNote: String,
  resolvedAt: Date,
  rating: Number,
  review: String,
  createdAt: { type: Date, default: Date.now },
});
const Ticket = mongoose.model('Ticket', ticketSchema);

const cleaningRequestSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  employeeName: String,
  department: String,
  floorNumber: String,
  deskNumber: String,
  cleaningType: String,
  status: { type: String, default: 'Pending' }, // Pending | In Progress | Completed
  chatHistory: [chatMessageSchema],
  completedBy: String,
  closingNote: String,
  completedAt: Date,
  rating: Number,
  review: String,
  createdAt: { type: Date, default: Date.now },
});
const CleaningRequest = mongoose.model('CleaningRequest', cleaningRequestSchema);

const orderSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  employeeName: String,
  beverage: String,
  status: { type: String, default: 'Pending' }, // Pending | Completed
  completedAt: Date,
  createdAt: { type: Date, default: Date.now },
  // Optional: an amount field to track spend per order; if missing in existing docs, treat as 0
  amount: { type: Number, default: 0 }
});
const Order = mongoose.model('Order', orderSchema);

// =================================================================
/* Middleware */
// =================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files and allow extensionless .html
app.use(express.static(__dirname, { extensions: ['html'] })); // extensionless static pages [2]

const sessionMiddleware = session({
  secret: 'a_very_secret_key_for_jc_nexus_hub',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI }),
  cookie: { maxAge: 1000*60*60*24 },
});
app.use(sessionMiddleware);

// Share session with Socket.IO per official guidance
io.engine.use(sessionMiddleware); // direct sharing (Socket.IO v4+) [8]

// Helpers
const isAuthenticated = (req,res,next)=> req.session.userId ? next() : res.redirect('/');
const hasRole = (...roles)=>(req,res,next)=> (req.session.userRole && roles.includes(req.session.userRole)) ? next() : res.status(403).send('<h1>403 Forbidden</h1>');

// =================================================================
/* HTML Routes / Aliases */
// =================================================================
app.get('/', (req,res)=>{
  if (req.session.userId){
    switch(req.session.userRole){
      case 'Admin':    return res.redirect('/admin-dashboard.html');
      case 'IT':       return res.redirect('/it-dashboard.html');
      case 'Cleaning': return res.redirect('/cleaning-dashboard.html');
      case 'Canteen':  return res.redirect('/canteen-dashboard.html');
      default:         return res.redirect('/employee-dashboard.html');
    }
  }
  res.sendFile(path.join(__dirname,'index.html'));
});
app.get('/register', (req,res)=> res.sendFile(path.join(__dirname,'register.html')));

app.get('/employee-dashboard.html', isAuthenticated, hasRole('Employee','Admin'), (req,res)=> res.sendFile(path.join(__dirname,'employee-dashboard.html')));
app.get('/admin-dashboard.html',    isAuthenticated, hasRole('Admin'),          (req,res)=> res.sendFile(path.join(__dirname,'admin-dashboard.html')));
app.get('/it-dashboard.html',       isAuthenticated, hasRole('IT','Admin'),     (req,res)=> res.sendFile(path.join(__dirname,'it-dashboard.html')));
app.get('/cleaning-dashboard.html', isAuthenticated, hasRole('Cleaning','Admin'),(req,res)=> res.sendFile(path.join(__dirname,'cleaning-dashboard.html')));
app.get('/canteen-dashboard.html',  isAuthenticated, hasRole('Canteen','Admin'),(req,res)=> res.sendFile(path.join(__dirname,'canteen-dashboard.html')));

// New: User Management page (Admin-only)
app.get('/user-management.html', isAuthenticated, hasRole('Admin'), (req,res)=> res.sendFile(path.join(__dirname,'user-management.html')));

// Resolved pages
app.get('/it-resolved',       isAuthenticated, hasRole('IT','Admin'),       (req,res)=> res.sendFile(path.join(__dirname,'it-resolved.html')));
app.get('/cleaning-resolved', isAuthenticated, hasRole('Cleaning','Admin'), (req,res)=> res.sendFile(path.join(__dirname,'cleaning-resolved.html')));

// aliases without .html
app.get('/employee-dashboard', (req,res)=> res.redirect('/employee-dashboard.html'));
app.get('/admin-dashboard',    (req,res)=> res.redirect('/admin-dashboard.html'));
app.get('/it-dashboard',       (req,res)=> res.redirect('/it-dashboard.html'));
app.get('/cleaning-dashboard', (req,res)=> res.redirect('/cleaning-dashboard.html'));
app.get('/canteen-dashboard',  (req,res)=> res.redirect('/canteen-dashboard.html'));

// feature pages
app.get('/submit-ticket',    isAuthenticated, hasRole('Employee','Admin'), (req,res)=> res.sendFile(path.join(__dirname,'submit-ticket.html')));
app.get('/order-beverage',   isAuthenticated, hasRole('Employee','Admin'), (req,res)=> res.sendFile(path.join(__dirname,'order-beverage.html')));
app.get('/request-cleaning', isAuthenticated, hasRole('Employee','Admin'), (req,res)=> res.sendFile(path.join(__dirname,'request-cleaning.html')));

app.get('/logout', (req,res)=>{
  const sid = req.session.id;
  req.session.destroy(()=>{
    res.clearCookie('connect.sid');
    io.in(sid).disconnectSockets(true);
    res.redirect('/');
  });
});

// =================================================================
/* Auth APIs */
// =================================================================
app.post('/api/register', async (req,res)=>{
  try{
    const { fullName,email,employeeId,department,role,password } = req.body;
    if (!fullName||!email||!employeeId||!department||!role||!password) return res.status(400).json({message:'All fields are required.'});
    const existing = await User.findOne({ $or:[{email},{employeeId}] });
    if (existing) return res.status(409).json({message:(existing.email===email?'Email':'Employee ID')+' already exists.'});
    const hashed = await bcrypt.hash(password,10);
    const user = await User.create({ fullName,email,employeeId,department,role,password:hashed });
    req.session.userId = user._id; req.session.userRole = user.role; req.session.fullName = user.fullName; req.session.employeeId = user.employeeId;
    res.status(201).json({success:true,message:'Registration successful.'});
  }catch(e){ console.error('Register error:',e); res.status(500).json({message:'Server error during registration.'}); }
});
app.post('/api/login', async (req,res)=>{
  try{
    const { email,password } = req.body;
    const user = await User.findOne({email}); if(!user) return res.status(400).json({message:'Invalid credentials.'});
    const ok = await bcrypt.compare(password,user.password); if(!ok) return res.status(400).json({message:'Invalid credentials.'});
    req.session.userId = user._id; req.session.userRole = user.role; req.session.fullName = user.fullName; req.session.employeeId = user.employeeId;
    let redirectTo = '/employee-dashboard.html';
    if (user.role==='Admin') redirectTo='/admin-dashboard.html';
    else if (user.role==='IT') redirectTo='/it-dashboard.html';
    else if (user.role==='Cleaning') redirectTo='/cleaning-dashboard.html';
    else if (user.role==='Canteen') redirectTo='/canteen-dashboard.html';
    res.json({success:true,redirect:redirectTo});
  }catch{ res.status(500).json({message:'Server error during login.'}); }
});
app.get('/api/user-info', isAuthenticated, (req,res)=> res.json({ fullName:req.session.fullName, role:req.session.userRole, employeeId:req.session.employeeId }));

// =================================================================
/* Employee APIs (My Requests + Create) */
// =================================================================
app.get('/api/employee/my-requests', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const employeeId = req.session.employeeId;
    const [tickets, orders, cleaning] = await Promise.all([
      Ticket.find({employeeId}).sort({createdAt:-1}),
      Order.find({employeeId}).sort({createdAt:-1}),
      CleaningRequest.find({employeeId}).sort({createdAt:-1}),
    ]);
    res.json({tickets,orders,cleaning});
  }catch{ res.status(500).json({message:'Server error loading requests.'}); }
});
app.post('/api/tickets', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const { mainIssue,problemDescription,floorNumber,tableNumber,department } = req.body;
    const t = await Ticket.create({
      employeeId:req.session.employeeId, employeeName:req.session.fullName,
      department:department||'', floorNumber:floorNumber||'', tableNumber:tableNumber||'',
      mainIssue, problemDescription, status:'Pending'
    });
    io.emit('new-ticket', { ticketId:t._id });
    res.status(201).json(t);
  }catch{ res.status(500).json({message:'Server error creating ticket.'}); }
});
app.get('/api/tickets/details/:id', isAuthenticated, async (req,res)=>{
  try{ const t = await Ticket.findById(req.params.id); res.json(t); }
  catch{ res.status(500).json({message:'Server error loading ticket.'}); }
});
app.post('/api/tickets/submit-rating', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const { ticketId,rating,review } = req.body;
    const updated = await Ticket.findOneAndUpdate(
      { _id:ticketId, employeeId:req.session.employeeId },
      { rating:Number(rating), review:review||'' }, { new:true }
    );
    res.json(updated);
  }catch{ res.status(500).json({message:'Server error saving rating.'}); }
});
app.post('/api/beverage/orders', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const { beverage, amount } = req.body; // amount optional
    const order = await Order.create({
      employeeId:req.session.employeeId, employeeName:req.session.fullName, beverage, status:'Pending', amount: Number(amount)||0
    });
    io.emit('new-order', { orderId:order._id });
    res.status(201).json(order);
  }catch{ res.status(500).json({message:'Server error creating order.'}); }
});
app.post('/api/cleaning/requests', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const { floorNumber,deskNumber,cleaningType,department } = req.body;
    const c = await CleaningRequest.create({
      employeeId:req.session.employeeId, employeeName:req.session.fullName,
      department:department||'', floorNumber, deskNumber, cleaningType, status:'Pending'
    });
    io.emit('new-cleaning', { requestId:c._id });
    res.status(201).json(c);
  }catch{ res.status(500).json({message:'Server error creating cleaning request.'}); }
});
app.get('/api/cleaning/details/:id', isAuthenticated, async (req,res)=>{
  try{ const c = await CleaningRequest.findById(req.params.id); res.json(c); }
  catch{ res.status(500).json({message:'Server error loading cleaning request.'}); }
});
app.post('/api/cleaning/submit-rating', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const { requestId,rating,review } = req.body;
    const updated = await CleaningRequest.findOneAndUpdate(
      { _id:requestId, employeeId:req.session.employeeId },
      { rating:Number(rating), review:review||'' }, { new:true }
    );
    res.json(updated);
  }catch{ res.status(500).json({message:'Server error saving rating.'}); }
});

// =================================================================
/* IT staff APIs */
// =================================================================
app.get('/api/it/summary', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
  try{
    const today = new Date(); today.setHours(0,0,0,0);
    const [total,pending,inProgress,resolvedToday] = await Promise.all([
      Ticket.countDocuments({ status:{ $ne:'Resolved' } }),
      Ticket.countDocuments({ status:'Pending' }),
      Ticket.countDocuments({ status:'In Progress' }),
      Ticket.countDocuments({ resolvedAt:{ $gte:today } }),
    ]);
    res.json({ counts:{ total,pending,inProgress,resolvedToday } });
  }catch{ res.status(500).send('Server Error'); }
});
app.get('/api/tickets/:status', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
  try{
    const { status } = req.params;
    const query = (status==='all') ? { status:{ $ne:'Resolved' } } : { status };
    const tickets = await Ticket.find(query).sort({createdAt:-1});
    res.json(tickets);
  }catch{ res.status(500).send('Server error'); }
});
app.post('/api/tickets/update-status', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
  try{
    const { ticketId,status } = req.body;
    const ticket = await Ticket.findByIdAndUpdate(ticketId,{status},{new:true});
    io.emit('ticket-updated', ticket);
    if (status==='Resolved') io.emit('ticket-resolved-notification',{ticketId});
    res.json(ticket);
  }catch{ res.status(500).send('Server error'); }
});
app.post('/api/tickets/resolve', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
  try{
    const { ticketId,resolutionNote } = req.body;
    const ticket = await Ticket.findByIdAndUpdate(
      ticketId,
      { status:'Resolved', resolutionNote, resolvedBy:req.session.fullName, resolvedAt:new Date() },
      { new:true }
    );
    io.emit('ticket-updated', ticket);
    io.emit('ticket-resolved-notification',{ticketId});
    res.json(ticket);
  }catch{ res.status(500).send('Server error'); }
});

// =================================================================
/* Cleaning staff APIs */
// =================================================================
app.get('/api/cleaning/summary', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
  try{
    const today = new Date(); today.setHours(0,0,0,0);
    const [total,pending,inProgress,completedToday] = await Promise.all([
      CleaningRequest.countDocuments({}),
      CleaningRequest.countDocuments({ status:'Pending' }),
      CleaningRequest.countDocuments({ status:'In Progress' }),
      CleaningRequest.countDocuments({ completedAt:{ $gte:today } }),
    ]);
    res.json({ counts:{ total,pending,inProgress,completedToday } });
  }catch{ res.status(500).send('Server Error'); }
});
app.get('/api/cleaning/list/:status', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
  try{
    const { status } = req.params;
    const query = (status==='all')
      ? { status: { $in: ['Pending','In Progress'] } }
      : { status };
    const rows = await CleaningRequest.find(query).sort({ createdAt:-1 });
    res.json(rows);
  }catch{ res.status(500).send('Server error'); }
});
app.post('/api/cleaning/update-status', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
  try{
    const { requestId,status,closingNote } = req.body;
    const update = { status };
    if (status==='Completed'){
      update.completedAt = new Date();
      update.completedBy = req.session.fullName;
      if (closingNote) update.closingNote = closingNote;
    }
    const row = await CleaningRequest.findByIdAndUpdate(requestId, update, { new:true });
    io.emit('cleaning-updated', row);
    if (status==='Completed') io.emit('cleaning-completed-notification',{ requestId });
    res.json(row);
  }catch{ res.status(500).send('Server error'); }
});

// =================================================================
/* Cleaning Resolved APIs */
// =================================================================
app.get('/api/cleaning/resolved-summary', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
  try{
    const ninetyDaysAgo = new Date(Date.now() - 90*24*60*60*1000);
    const requests = await CleaningRequest.find({ status:'Completed', completedAt: { $gte: ninetyDaysAgo } })
      .sort({ completedAt: -1 });
    const totalCompleted = requests.length;

    let averageCompletionTime = '0h 0m';
    if (totalCompleted > 0) {
      const totalMs = requests.reduce((acc, r)=>{
        if (r.completedAt && r.createdAt) return acc + (r.completedAt - r.createdAt);
        return acc;
      }, 0);
      const avgMs = totalMs / totalCompleted || 0;
      const hours = Math.floor(avgMs / 3600000);
      const minutes = Math.floor((avgMs % 3600000) / 60000);
      averageCompletionTime = `${hours}h ${minutes}m`;
    }

    res.json({
      summary: { totalCompleted, averageCompletionTime },
      requests
    });
  }catch(e){
    console.error('resolved-summary error', e);
    res.status(500).json({ message:'Server error loading resolved summary.' });
  }
});
app.get('/api/cleaning/resolved', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
  try{
    const rows = await CleaningRequest.find({ status:'Completed' }).sort({ completedAt:-1 });
    res.json(rows);
  }catch{ res.status(500).send('Server error'); }
});

// =================================================================
/* CANTEEN staff APIs */
// =================================================================
app.get('/api/canteen/summary', isAuthenticated, hasRole('Canteen','Admin'), async (req,res)=>{
  try{
    const today = new Date(); today.setHours(0,0,0,0);
    const [total,pending,completedToday] = await Promise.all([
      Order.countDocuments({}),
      Order.countDocuments({ status:'Pending' }),
      Order.countDocuments({ completedAt:{ $gte:today } }),
    ]);
    res.json({ counts:{ total,pending,completedToday } });
  }catch{ res.status(500).send('Server Error'); }
});
app.get('/api/canteen/orders/:status', isAuthenticated, hasRole('Canteen','Admin'), async (req,res)=>{
  try{
    const { status } = req.params; // all | Pending | Completed
    const query = (status==='all') ? {} : { status };
    const rows = await Order.find(query).sort({ createdAt:-1 });
    res.json(rows);
  }catch{ res.status(500).send('Server error'); }
});
app.post('/api/canteen/orders/update-status', isAuthenticated, hasRole('Canteen','Admin'), async (req,res)=>{
  try{
    const { orderId, status } = req.body; // Pending | Completed
    const update = { status };
    if (status==='Completed') update.completedAt = new Date();
    const row = await Order.findByIdAndUpdate(orderId, update, { new:true });
    io.emit('canteen-updated', row);
    if (status==='Completed') io.emit('canteen-completed-notification', { orderId });
    res.json(row);
  }catch{ res.status(500).send('Server error'); }
});

// =================================================================
/* Admin: User Management APIs */
// =================================================================

// List all users with lightweight info
app.get('/api/admin/users', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const users = await User.find({}, { password: 0 }).sort({ createdAt: -1 });
    res.json(users);
  }catch{ res.status(500).json({ message:'Server error listing users.' }); }
});

// Get single user details (without password)
app.get('/api/admin/users/:id', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const user = await User.findById(req.params.id, { password: 0 });
    if (!user) return res.status(404).json({ message:'User not found' });
    res.json(user);
  }catch{ res.status(500).json({ message:'Server error fetching user.' }); }
});

// Create user (Admin)
app.post('/api/admin/users', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const { fullName,email,employeeId,department,role,password } = req.body;
    if (!fullName||!email||!employeeId||!role||!password) return res.status(400).json({message:'Missing required fields.'});
    const existing = await User.findOne({ $or:[{email},{employeeId}] });
    if (existing) return res.status(409).json({message:(existing.email===email?'Email':'Employee ID')+' already exists.'});
    const hashed = await bcrypt.hash(password,10);
    const created = await User.create({ fullName,email,employeeId,department:department||'',role,password:hashed });
    res.status(201).json({ ...created.toObject(), password: undefined });
  }catch{ res.status(500).json({ message:'Server error creating user.' }); }
});

// Update user (Admin) — if password provided, rehash
app.put('/api/admin/users/:id', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const { fullName,email,employeeId,department,role,password } = req.body;
    const update = { fullName,email,employeeId,department,role };
    Object.keys(update).forEach(k=> (update[k]===undefined) && delete update[k]);
    if (password) {
      update.password = await bcrypt.hash(password,10);
    }
    // Enforce unique email/employeeId
    if (email || employeeId){
      const dup = await User.findOne({ 
        $and: [
          { _id: { $ne: req.params.id } },
          { $or: [ email ? { email } : null, employeeId ? { employeeId } : null ].filter(Boolean) }
        ]
      });
      if (dup) return res.status(409).json({ message: 'Email or Employee ID already exists.' });
    }
    const updated = await User.findByIdAndUpdate(req.params.id, update, { new:true, projection: { password: 0 } });
    if (!updated) return res.status(404).json({ message:'User not found' });
    res.json(updated);
  }catch{ res.status(500).json({ message:'Server error updating user.' }); }
});

// Delete user (Admin) — optional: also soft-delete or anonymize references
app.delete('/api/admin/users/:id', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const id = req.params.id;
    // Prevent self-delete if desired
    if (req.session.userId === id) return res.status(400).json({ message:'Cannot delete current logged-in admin.' });
    const deleted = await User.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ message:'User not found' });
    // Optionally: emit to admin clients
    io.emit('admin-user-removed', { userId: id });
    res.json({ success: true });
  }catch{ res.status(500).json({ message:'Server error deleting user.' }); }
});

// Per-user history: tickets, cleaning, orders
app.get('/api/admin/users/:id/history', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message:'User not found' });
    const employeeId = user.employeeId;
    const [tickets, cleaning, orders] = await Promise.all([
      Ticket.find({ employeeId }).sort({ createdAt: -1 }),
      CleaningRequest.find({ employeeId }).sort({ createdAt: -1 }),
      Order.find({ employeeId }).sort({ createdAt: -1 })
    ]);
    res.json({ tickets, cleaning, orders });
  }catch{ res.status(500).json({ message:'Server error fetching history.' }); }
});

// Per-user spend: total and breakdown from Order.amount
app.get('/api/admin/users/:id/spend', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message:'User not found' });
    const employeeId = user.employeeId;
    const agg = await Order.aggregate([
      { $match: { employeeId } },
      { $group: { _id: '$beverage', total: { $sum: { $ifNull: ['$amount', 0] } }, count: { $sum: 1 } } },
    ]);
    const total = agg.reduce((a,b)=> a + (b.total||0), 0);
    res.json({ total, breakdown: agg });
  }catch{ res.status(500).json({ message:'Server error calculating spend.' }); }
});

// Global admin dashboard summary for your admin dashboard JS
app.get('/api/admin/summary', isAuthenticated, hasRole('Admin'), async (req,res)=>{
  try{
    const today = new Date(); today.setHours(0,0,0,0);
    const [usersCount, pendingTickets, completedOrdersToday] = await Promise.all([
      User.countDocuments({}),
      Ticket.countDocuments({ status: 'Pending' }),
      Order.countDocuments({ completedAt: { $gte: today } })
    ]);
    const byService = [
      { _id: 'IT Tickets (Open)', count: await Ticket.countDocuments({ status: { $in: ['Pending','In Progress'] } }) },
      { _id: 'Cleaning (Live)', count: await CleaningRequest.countDocuments({ status: { $in: ['Pending','In Progress'] } }) },
      { _id: 'Canteen Orders (Pending)', count: await Order.countDocuments({ status: 'Pending' }) }
    ];
    const liveFeed = (await Promise.all([
      Ticket.find({}).sort({ createdAt: -1 }).limit(10).lean().then(arr=>arr.map(a=>({ createdAt:a.createdAt, employeeName:a.employeeName, type:'IT Ticket', details:a.mainIssue, status:a.status }))),
      CleaningRequest.find({}).sort({ createdAt: -1 }).limit(10).lean().then(arr=>arr.map(a=>({ createdAt:a.createdAt, employeeName:a.employeeName, type:'Cleaning', details:a.cleaningType, status:a.status }))),
      Order.find({}).sort({ createdAt: -1 }).limit(10).lean().then(arr=>arr.map(a=>({ createdAt:a.createdAt, employeeName:a.employeeName, type:'Order', details:a.beverage, status:a.status }))),
    ])).flat().sort((a,b)=> new Date(b.createdAt) - new Date(a.createdAt)).slice(0,15);

    res.json({
      counts: { users: usersCount, pending: pendingTickets, completedToday: completedOrdersToday },
      charts: { byService },
      liveFeed
    });
  }catch(e){
    console.error('admin summary error', e);
    res.status(500).json({ message:'Server error loading admin summary.' });
  }
});

// =================================================================
/* Socket.IO Logic (incl. chat + realtime notifications) */
// =================================================================
io.on('connection', (socket)=>{
  const sess = socket.request.session;
  if (!sess || !sess.userId) return socket.disconnect();

  // Join a personal room by session id for targeted disconnect on logout
  socket.join(sess.id);

  // Ticket chat
  socket.on('join-ticket-room', (ticketId)=> socket.join(ticketId));
  socket.on('send-chat-message', async ({ ticketId,message })=>{
    try{
      const chatMessage = { senderId:sess.userId, senderName:sess.fullName, senderRole:sess.userRole, message };
      const t = await Ticket.findByIdAndUpdate(ticketId, { $push:{ chatHistory:chatMessage } }, { new:true });
      if (t) io.to(ticketId).emit('new-chat-message', { ticketId, chatMessage });
    }catch(e){ console.error('ticket chat error', e); }
  });

  // Cleaning chat
  socket.on('join-cleaning-room', (requestId)=> socket.join(`clean:${requestId}`));
  socket.on('send-cleaning-message', async ({ requestId,message })=>{
    try{
      const chatMessage = { senderId:sess.userId, senderName:sess.fullName, senderRole:sess.userRole, message };
      const c = await CleaningRequest.findByIdAndUpdate(requestId, { $push:{ chatHistory:chatMessage } }, { new:true });
      if (c) io.to(`clean:${requestId}`).emit('new-cleaning-message', { requestId, chatMessage });
    }catch(e){ console.error('cleaning chat error', e); }
  });

  socket.on('disconnect', ()=>{});
});

// =================================================================
/* Start */
// =================================================================
server.listen(PORT, ()=> console.log(`JC Nexus Hub server running on http://localhost:${PORT}`));
