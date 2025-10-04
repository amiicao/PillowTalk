const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

// CRITICAL: Socket.IO CORS must allow ngrok domain
const io = socketIo(server, {
  cors: {
    origin: "*", // ngrok URLs change, so we allow all but use token auth
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1e6 // 1MB limit
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// CRITICAL: Rate limiting to prevent attacks
const createRoomLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many rooms created, try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const passwordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many password attempts, try again later',
  standardHeaders: true,
  legacyHeaders: false
});

// Store active rooms
const rooms = new Map();
const ROOM_EXPIRY = 6 * 60 * 60 * 1000; // 6 hours (reasonable for a call with friends)

// Validation helpers
function isValidRoomId(roomId) {
  return typeof roomId === 'string' && /^[a-f0-9]{32}$/.test(roomId);
}

function isValidPassword(password) {
  return password && 
         password.length >= 6  
        //  /[A-Za-z]/.test(password) && 
        //  /[0-9]/.test(password);
}

// CRITICAL: Socket authentication middleware
io.use((socket, next) => {
  const { roomId, token } = socket.handshake.auth;
  
  if (!roomId || !isValidRoomId(roomId)) {
    return next(new Error('Invalid room'));
  }
  
  const room = rooms.get(roomId);
  if (!room || !room.active) {
    return next(new Error('Room not found'));
  }
  
  // CRITICAL: Verify auth token
  if (!token || token !== room.token) {
    return next(new Error('Unauthorized'));
  }
  
  socket.roomId = roomId;
  next();
});

// Clean expired rooms every hour
setInterval(() => {
  const now = Date.now();
  for (const [roomId, room] of rooms.entries()) {
    if (now - room.createdAt > ROOM_EXPIRY) {
      room.active = false;
      rooms.delete(roomId);
      console.log(`Expired room: ${roomId}`);
    }
  }
}, 60 * 60 * 1000);

// Create room with rate limiting
app.post('/api/create-room', createRoomLimiter, async (req, res) => {
  const { password } = req.body;
  
  if (!isValidPassword(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 6 characters' 
    });
  }

  try {
    const roomId = crypto.randomBytes(16).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 12);
    const token = crypto.randomBytes(32).toString('hex');

    rooms.set(roomId, {
      password: hashedPassword,
      token: token,
      participants: new Set(),
      active: true,
      createdAt: Date.now(),
      maxParticipants: 10
    });

    // Support both HTTP and HTTPS (ngrok provides HTTPS)
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');

    res.json({ 
      roomId,
      token, // Client needs this for socket auth
      link: `${protocol}://${host}/room.html?id=${roomId}`
    });

    console.log(`✅ Room created: ${roomId} (expires in 6 hours)`);
  } catch (error) {
    console.error('Error creating room:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify password with rate limiting
app.post('/api/verify-room', passwordLimiter, async (req, res) => {
  const { roomId, password } = req.body;

  if (!isValidRoomId(roomId)) {
    return res.status(400).json({ error: 'Invalid room ID' });
  }

  const room = rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: 'Room not found or expired' });
  }

  if (!room.active) {
    return res.status(403).json({ error: 'Room has ended' });
  }

  // Check expiry
  if (Date.now() - room.createdAt > ROOM_EXPIRY) {
    room.active = false;
    return res.status(403).json({ error: 'Room expired' });
  }

  try {
    const isValid = await bcrypt.compare(password, room.password);
    
    if (!isValid) {
      console.log(`❌ Failed password attempt for room: ${roomId}`);
      return res.status(401).json({ error: 'Incorrect password' });
    }

    console.log(`✅ Password verified for room: ${roomId}`);
    res.json({ 
      success: true,
      token: room.token // Send auth token
    });
  } catch (error) {
    console.error('Error verifying password:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// WebSocket signaling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  const roomId = socket.roomId; // Set by auth middleware

  socket.on('join-room', ({ userId }) => {
    const room = rooms.get(roomId);
    
    if (!room || !room.active) {
      socket.emit('room-error', { message: 'Room not available' });
      return;
    }

    if (room.participants.size >= room.maxParticipants) {
      socket.emit('room-error', { message: 'Room is full (max 10 people)' });
      return;
    }

    socket.join(roomId);
    socket.userId = userId;
    
    const existingUsers = Array.from(room.participants);
    room.participants.add(socket.id);

    console.log(`User ${socket.id} joined room ${roomId} (${room.participants.size} total)`);

    socket.emit('existing-users', existingUsers);
    socket.to(roomId).emit('user-connected', socket.id);
  });

  // WebRTC signaling
  socket.on('offer', ({ to, offer, from }) => {
    io.to(to).emit('offer', { from, offer });
  });

  socket.on('answer', ({ to, answer, from }) => {
    io.to(to).emit('answer', { from, answer });
  });

  socket.on('ice-candidate', ({ to, candidate, from }) => {
    io.to(to).emit('ice-candidate', { from, candidate });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    
    if (roomId) {
      const room = rooms.get(roomId);
      
      if (room) {
        room.participants.delete(socket.id);
        socket.to(roomId).emit('user-disconnected', socket.id);
        
        console.log(`Room ${roomId} now has ${room.participants.size} participants`);
        
        if (room.participants.size === 0) {
          room.active = false;
          console.log(`Room ${roomId} ended (empty)`);
          setTimeout(() => rooms.delete(roomId), 60000);
        }
      }
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════╗
║  ☁️ Video Call Server Ready                    ║
╟────────────────────────────────────────────────╢
║  Local:  http://localhost:${PORT}              ║
║                                                ║
║  🔒 Security Features:                         ║
║  ✅ Socket authentication                      ║
║  ✅ Rate limiting (5 rooms/15min)              ║
║  ✅ Password validation (6+ chars)             ║
║  ✅ Room expiry (6 hours)                      ║
║  ✅ Max 10 participants per room               ║
╚════════════════════════════════════════════════╝

  `);
});