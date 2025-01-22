const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../../models/user'); // Adjust the path as per your structure

const router = express.Router();

// Signup Route
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, photo } = req.body;

    if (!name || !email || !password || !photo) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      photo,
    });

    const savedUser = await newUser.save();

    res.status(201).json({ message: 'User signed up successfully!' });
  } catch (error) {
    console.error('Error in signup route:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

module.exports = router;
