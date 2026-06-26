const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// ── Mock company users DB (replace with real DB later) ───────────────
// All demo accounts use password: demo1234
const COMPANY_USERS = [
  {
    id: 'u001',
    identifier: 'EMP001',
    email: 'john.doe@classygroup.com',
    mobile: '9876543210',
    passwordHash: bcrypt.hashSync('demo1234', 10),
    name: 'John Doe',
    role: 'Project Manager',
    company: 'Classy Group Construction & Interior Solutions',
    companyCode: 'CG',
    department: 'Projects',
    avatar: 'JD',
  },
  {
    id: 'u002',
    identifier: 'EMP002',
    email: 'demo@constructerp.com',
    mobile: '9000000001',
    passwordHash: bcrypt.hashSync('demo1234', 10),
    name: 'Jennifer Cole',
    role: 'Company Administrator',
    company: 'Classy Group Construction & Interior Solutions',
    companyCode: 'CG',
    department: 'Administration',
    avatar: 'JC',
  },
  {
    id: 'u003',
    identifier: 'EMP003',
    email: 'admin@classygroup.com',
    mobile: '9000000002',
    passwordHash: bcrypt.hashSync('demo1234', 10),
    name: 'Admin User',
    role: 'HR Manager',
    company: 'Classy Group Construction & Interior Solutions',
    companyCode: 'CG',
    department: 'HR',
    avatar: 'AU',
  },
];

// ── POST /api/auth/login ─────────────────────────────────────────────
router.post(
  '/login',
  [
    body('identifier').trim().notEmpty().withMessage('Employee ID / Email / Mobile is required.'),
    body('password').isLength({ min: 4 }).withMessage('Password must be at least 4 characters.'),
  ],
  async (req, res) => {
    // Validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, errors: errors.array() });
    }

    const { identifier, password, rememberDevice } = req.body;

    try {
      // Find user by ID, email, or mobile
      const user = COMPANY_USERS.find(
        (u) =>
          u.identifier.toLowerCase() === identifier.toLowerCase() ||
          u.email.toLowerCase() === identifier.toLowerCase() ||
          u.mobile === identifier
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials. Please check your ID, email or mobile.',
        });
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials. Please check your password.',
        });
      }

      // Generate JWT
      const token = jwt.sign(
        {
          id: user.id,
          role: 'company_user',
          company: user.company,
          name: user.name,
        },
        process.env.JWT_SECRET,
        { expiresIn: rememberDevice ? '30d' : '8h' }
      );

      // Log the access
      console.log(`[AUTH] Company login: ${user.name} (${user.email}) at ${new Date().toISOString()}`);

      return res.json({
        success: true,
        message: 'Login successful. Welcome back!',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          company: user.company,
          companyCode: user.companyCode,
          department: user.department,
          avatar: user.avatar,
        },
      });
    } catch (err) {
      console.error('[AUTH ERROR]', err);
      return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
  }
);

// ── POST /api/auth/logout ─────────────────────────────────────────────
router.post('/logout', (req, res) => {
  // In production: invalidate token (Redis blacklist / DB flag)
  res.json({ success: true, message: 'Logged out successfully.' });
});

module.exports = router;
