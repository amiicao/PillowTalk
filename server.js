const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(express.json());
app.use(express.static('public'));

// Store active rooms in memory
// Structure: { roomId: { password: hashedPassword, participants: Set, active: boolean } }
const rooms = new Map();

// Create a new room
app.post('/api/create-room', async (req, res) => {
  const { password } = req.body;
  
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  const roomId = crypto.randomBytes(16).toString('hex');
  const hashedPassword = await bcrypt.hash(password, 10);

  rooms.set(roomId, {
    password: hashedPassword,
    participants: new Set(),
    active: true,
    createdAt: Date.now()
  });

  res.json({ 
    roomId, 
    link: `${req.protocol}://${req.get('host')}/room.html?id=${roomId}` 
  });
});

// Verify room password
app.post('/api/verify-room', async (req, res) => {
  const { roomId, password } = req.body;

  const room = rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: 'Room not found or has ended' });
  }

  if (!room.active) {
    return res.status(403).json({ error: 'This room has ended' });
  }

  const isValid = await bcrypt.compare(password, room.password);
  
  if (!isValid) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  res.json({ success: true });
});

// WebSocket signaling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', ({ roomId, userId }) => {
    const room = rooms.get(roomId);
    
    if (!room || !room.active) {
      socket.emit('room-error', { message: 'Room not found or has ended' });
      return;
    }

    socket.join(roomId);
    socket.roomId = roomId;
    socket.userId = userId;
    
    // Get existing participants BEFORE adding new one
    const existingUsers = Array.from(room.participants);
    
    // Add new participant
    room.participants.add(socket.id);

    console.log(`User ${socket.id} (${userId}) joined room ${roomId}`);
    console.log(`Existing participants:`, existingUsers);
    console.log(`Total participants now: ${room.participants.size}`);

    // Send list of existing participants to the new user
    socket.emit('existing-users', existingUsers);

    // Notify existing users about the new participant
    socket.to(roomId).emit('user-connected', socket.id);
    console.log(`Notified room ${roomId} about new user: ${socket.id}`);
  });

  // WebRTC signaling events
  socket.on('offer', ({ to, offer, from }) => {
    console.log(`Relaying offer from ${from} to ${to}`);
    io.to(to).emit('offer', { from, offer });
  });

  socket.on('answer', ({ to, answer, from }) => {
    console.log(`Relaying answer from ${from} to ${to}`);
    io.to(to).emit('answer', { from, answer });
  });

  socket.on('ice-candidate', ({ to, candidate, from }) => {
    console.log(`Relaying ICE candidate from ${from} to ${to}`);
    io.to(to).emit('ice-candidate', { from, candidate });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    
    if (socket.roomId) {
      const room = rooms.get(socket.roomId);
      
      if (room) {
        room.participants.delete(socket.id);
        
        // Notify others in the room using socket.id (not userId)
        socket.to(socket.roomId).emit('user-disconnected', socket.id);
        console.log(`Notified room ${socket.roomId} that ${socket.id} disconnected`);
        
        console.log(`Room ${socket.roomId} now has ${room.participants.size} participants`);
        
        // If room is empty, mark it as inactive
        if (room.participants.size === 0) {
          room.active = false;
          console.log(`Room ${socket.roomId} has ended (no participants)`);
          
          // Clean up room after some time
          setTimeout(() => {
            rooms.delete(socket.roomId);
            console.log(`Room ${socket.roomId} deleted from memory`);
          }, 60000); // Delete after 1 minute
        }
      }
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});