require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { connectDB } = require('./db');
const userRouter = require('./routes/user');
const adminRouter = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

connectDB();

app.use(express.json());
app.use(cors());

app.use('/users', userRouter);
app.use('/admin', adminRouter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
