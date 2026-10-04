const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const router = express.Router();
const prisma = new PrismaClient();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, '..', 'uploads', 'avatars');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-local-key-for-jwt';

// Helper for Real Email Sending
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendOtpEmail = async (email, otp) => {
  try {
    // Check if SMTP is configured
    if (!process.env.SMTP_USER || process.env.SMTP_USER === 'your-email@gmail.com') {
      console.log('--- DEVELOPMENT MODE: SMTP NOT CONFIGURED ---');
      console.log(`Verification code for ${email}: ${otp}`);
      console.log('---------------------------------------------');
      return true;
    }

    await transporter.sendMail({
      from: `"Security Audit" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Security Audit - Verify Your Email',
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #0f172a;">Security Audit</h2>
          <p>Thank you for registering. Please use the following 6-digit code to verify your email address:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #ef4444; margin: 20px 0;">${otp}</div>
          <p>This code will expire in 15 minutes.</p>
          <hr style="border-top: 1px solid #eee; margin-top: 30px;" />
          <p style="font-size: 12px; color: #94a3b8;">If you didn't request this, you can safely ignore this email.</p>
        </div>
      `
    });
    console.log(`Real OTP Email sent to: ${email}`);
    return true;
  } catch (error) {
    console.error("Nodemailer failed to send email. Falling back to console log. Error:", error);
    console.log('--- FALLBACK OTP ---');
    console.log(`Verification code for ${email}: ${otp}`);
    console.log('--------------------');
    // We log but don't throw, so the user can still register locally
    return true;
  }
};

// Register User
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'An account with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name: name || email.split('@')[0],
        isVerified: false,
        otp,
        otpExpiry,
      }
    });

    await sendOtpEmail(email, otp);

    res.status(201).json({
      success: true,
      message: 'OTP sent to email',
      email: newUser.email
    });

  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and verification code are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    if (user.otp !== otp || new Date() > new Date(user.otpExpiry)) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    // Mark as verified
    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, otp: null, otpExpiry: null }
    });

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        displayPicture: user.displayPicture
      }
    });

  } catch (error) {
    console.error('OTP Verification Error:', error);
    res.status(500).json({ error: 'Server error during verification' });
  }
});

// Login User
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email first. Contact support if you did not receive a code.', requiresOtp: true, email: user.email });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        displayPicture: user.displayPicture
      }
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// GET Current User (Verify Token)
router.get('/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, name: true, displayPicture: true }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// Update Current User Profile
router.put('/profile', upload.single('displayPicture'), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    // Check if the user exists
    const existingUser = await prisma.user.findUnique({
      where: { id: decoded.userId }
    });

    if (!existingUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updateData = {};
    if (req.body.name) {
      updateData.name = req.body.name;
    }

    if (req.file) {
      // Read file from disk and convert to base64 to store in MongoDB instead of ephemeral cloud run disk
      const fileData = fs.readFileSync(req.file.path);
      const b64 = fileData.toString('base64');
      updateData.displayPicture = `data:${req.file.mimetype};base64,${b64}`;
      
      // Clean up the temporary file
      try {
        fs.unlinkSync(req.file.path);
      } catch (e) {
        console.error('Failed to cleanup temp file', e);
      }
    }

    const updatedUser = await prisma.user.update({
      where: { id: decoded.userId },
      data: updateData,
      select: { id: true, email: true, name: true, displayPicture: true }
    });

    res.json(updatedUser);
  } catch (error) {
    console.error('Profile Update Error:', error);
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      res.status(401).json({ error: 'Invalid or expired token' });
    } else {
      res.status(500).json({ error: 'Server error during profile update' });
    }
  }
});

// ─── Forgot Password — send OTP to email ─────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await prisma.user.findUnique({ where: { email } });
    // Always return 200 to prevent email enumeration attacks
    if (!user) return res.json({ success: true, message: 'If this email is registered, an OTP has been sent.' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await prisma.user.update({
      where: { email },
      data: { otp, otpExpiry }
    });

    // Send styled reset email
    if (!process.env.SMTP_USER || process.env.SMTP_USER === 'your-email@gmail.com') {
      console.log('--- DEV MODE: Password Reset OTP ---');
      console.log(`Reset OTP for ${email}: ${otp}`);
      console.log('------------------------------------');
    } else {
      await transporter.sendMail({
        from: `"AuditScope Security" <${process.env.SMTP_USER}>`,
        to: email,
        subject: 'AuditScope — Password Reset Code',
        html: `
          <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;border:1px solid #e2e8f0;border-radius:12px;color:#334155;">
            <div style="margin-bottom:24px;">
              <span style="font-size:22px;font-weight:800;color:#0f172a;">Audit</span><span style="font-size:22px;font-weight:800;color:#4f46e5;">Scope</span>
            </div>
            <h2 style="margin:0 0 8px;color:#0f172a;font-size:20px;">Password Reset Request</h2>
            <p style="color:#64748b;font-size:14px;line-height:1.6;margin:0 0 24px;">Use the code below to reset your password. It expires in <strong>15 minutes</strong>.</p>
            <div style="background:#f1f5f9;border-radius:10px;padding:24px;text-align:center;margin-bottom:24px;">
              <div style="font-size:38px;font-weight:900;letter-spacing:10px;color:#4f46e5;">${otp}</div>
            </div>
            <p style="color:#94a3b8;font-size:12px;line-height:1.6;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
          </div>
        `
      });
    }

    console.log(`[Auth] Password reset OTP sent to ${email}`);
    res.json({ success: true, message: 'If this email is registered, an OTP has been sent.' });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Reset Password — verify OTP + set new password ──────────────────────────
router.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: 'Email, OTP, and new password are all required.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'No account found with this email.' });

    if (!user.otp || user.otp !== otp || !user.otpExpiry || new Date() > new Date(user.otpExpiry)) {
      return res.status(400).json({ error: 'Invalid or expired reset code. Please request a new one.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(newPassword, salt);

    await prisma.user.update({
      where: { email },
      data: { passwordHash, otp: null, otpExpiry: null }
    });

    console.log(`[Auth] Password reset successfully for ${email}`);
    res.json({ success: true, message: 'Password reset successfully. You can now log in.' });

  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

module.exports = router;
