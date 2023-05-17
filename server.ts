import express, { Request, Response, NextFunction } from 'express';
import mongoose, { Document } from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';

const app = express();
const port = 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/crud_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Define User interface and schema
interface IUser extends Document {
  username: string;
  password: string;
  role: 'admin' | 'user';
  loggedIn: boolean;
}

const userSchema = new mongoose.Schema<IUser>({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  loggedIn: { type: Boolean, default: false },
});

const User = mongoose.model<IUser>('User', userSchema);

// Middleware
app.use(express.json());

// Authentication middleware
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user as IUser;
    next();
  });
};

// Routes
app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  User.findOne({ username }, (err, user) => {
    if (err) return res.sendStatus(500);
    if (!user) return res.sendStatus(401);

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.sendStatus(500);
      if (!result) return res.sendStatus(401);

      const token = jwt.sign({ username, role: user.role }, 'secret');
      user.loggedIn = true;
      user.save();
      res.json({ token });
    });
  });
});

app.get('/users', authenticateToken, (req: Request, res: Response) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);

 
User.find({}, (err, users) => {
if (err) return res.sendStatus(500);
res.json(users);
});
});

app.post('/users', [
authenticateToken,
body('username').notEmpty(),
body('password').notEmpty(),
body('role').isIn(['admin', 'user']).optional(),
], (req: Request, res: Response) => {
if (req.user.role !== 'admin') return res.sendStatus(403);

const errors = validationResult(req);
if (!errors.isEmpty()) {
return res.status(400).json({ errors: errors.array() });
}

const { username, password, role } = req.body;

bcrypt.hash(password, 10, (err, hashedPassword) => {
if (err) return res.sendStatus(500);

const newUser = new User({ username, password: hashedPassword, role });
newUser.save((err, user) => {
  if (err) return res.sendStatus(500);
  res.json(user);
});
});
});

app.put('/users/:id', [
authenticateToken,
body('username').notEmpty(),
body('password').notEmpty().optional(),
body('role').isIn(['admin', 'user']).optional(),
], (req: Request, res: Response) => {
if (req.user.role !== 'admin') return res.sendStatus(403);

const errors = validationResult(req);
if (!errors.isEmpty()) {
return res.status(400).json({ errors: errors.array() });
}

const { username, password, role } = req.body;

User.findById(req.params.id, (err, user) => {
if (err) return res.sendStatus(500);
if (!user) return res.sendStatus(404);

user.username = username;
if (password) {
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.sendStatus(500);
    user.password = hashedPassword;
    user.role = role || user.role;
    user.save((err, updatedUser) => {
      if (err) return res.sendStatus(500);
      res.json(updatedUser);
    });
  });
} else {
  user.role = role || user.role;
  user.save((err, updatedUser) => {
    if (err) return res.sendStatus(500);
    res.json(updatedUser);
  });
}
});
});

app.delete('/users/:id', authenticateToken, (req: Request, res: Response) => {
if (req.user.role !== 'admin') return res.sendStatus(403);

User.findByIdAndDelete(req.params.id, (err, user) => {
if (err) return res.sendStatus(500);
if (!user) return res.sendStatus(404);
res.sendStatus(204);
});
});

// Start the server
app.listen(port, () => {
    console.log(Server is running on http://localhost:${port});
    });