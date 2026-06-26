const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// ── Super Admin Credential Store ─────────────────────────────────────
// Single super admin — username: Superadmin / password: Superadmin@123
const SUPER_ADMIN = {
  id: 'sa001',
  username: 'Superadmin',
  passwordHash: bcrypt.hashSync('Superadmin@123', 12),
  name: 'System Administrator',
  level: 'GLOBAL',
  nodeAccess: 'ALL',
  createdAt: '2024-01-01T00:00:00Z',
};

// ── Login attempt tracker (in-memory, replace with Redis in production) ──
const loginAttempts = new Map(); // key: IP, value: { count, lastAttempt, lockedUntil }
const MAX_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 min lockout

function checkBruteForce(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return { blocked: false };
  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    const remainSec = Math.ceil((record.lockedUntil - Date.now()) / 1000);
    return { blocked: true, remainSec };
  }
  if (record.lockedUntil && Date.now() >= record.lockedUntil) {
    loginAttempts.delete(ip);
    return { blocked: false };
  }
  return { blocked: false };
}

function recordFailedAttempt(ip) {
  const record = loginAttempts.get(ip) || { count: 0, lastAttempt: null, lockedUntil: null };
  record.count += 1;
  record.lastAttempt = Date.now();
  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCK_DURATION_MS;
    console.warn(`[ADMIN SECURITY] IP ${ip} locked out after ${MAX_ATTEMPTS} failed attempts.`);
  }
  loginAttempts.set(ip, record);
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

// ── JWT Auth Middleware ──────────────────────────────────────────────
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required. No token provided.',
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden. Super Admin privileges required.',
      });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    const message = err.name === 'TokenExpiredError'
      ? 'Session expired. Please log in again.'
      : 'Invalid session token. Access denied.';
    return res.status(401).json({ success: false, message });
  }
}

// ── POST /api/admin/login ────────────────────────────────────────────
router.post(
  '/login',
  [
    body('username').trim().notEmpty().withMessage('Username is required.'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, errors: errors.array() });
    }

    const { username, password, stayVerified } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // Check brute force lockout
    const bruteCheck = checkBruteForce(clientIp);
    if (bruteCheck.blocked) {
      console.warn(`[ADMIN SECURITY] Blocked login attempt from locked IP: ${clientIp}`);
      return res.status(429).json({
        success: false,
        message: `Account locked due to multiple failed attempts. Try again in ${Math.ceil(bruteCheck.remainSec / 60)} minute(s).`,
        locked: true,
        retryAfterSec: bruteCheck.remainSec,
      });
    }

    try {
      // Check username (case-sensitive)
      if (username !== SUPER_ADMIN.username) {
        recordFailedAttempt(clientIp);
        console.warn(`[ADMIN SECURITY] Failed login — invalid username: "${username}" from IP: ${clientIp}`);
        return res.status(401).json({
          success: false,
          message: 'Access denied. Invalid credentials. This attempt has been logged.',
          logged: true,
        });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, SUPER_ADMIN.passwordHash);
      if (!isMatch) {
        recordFailedAttempt(clientIp);
        console.warn(`[ADMIN SECURITY] Failed login — wrong password for "${username}" from IP: ${clientIp}`);
        return res.status(401).json({
          success: false,
          message: 'Access denied. Invalid credentials. This attempt has been logged.',
          logged: true,
        });
      }

      // Successful login — clear any failed attempts
      clearAttempts(clientIp);

      // Generate privileged JWT
      // stayVerified: true → 7 days, false → 4 hours
      const expiresIn = stayVerified ? '7d' : '4h';
      const token = jwt.sign(
        {
          id: SUPER_ADMIN.id,
          role: 'super_admin',
          level: SUPER_ADMIN.level,
          nodeAccess: SUPER_ADMIN.nodeAccess,
          username: SUPER_ADMIN.username,
          name: SUPER_ADMIN.name,
        },
        process.env.JWT_SECRET,
        { expiresIn }
      );

      console.log(`[ADMIN AUTH] ✅ Super Admin login: ${SUPER_ADMIN.name} from IP: ${clientIp} at ${new Date().toISOString()} | Session: ${expiresIn}`);

      return res.json({
        success: true,
        message: 'Secure session initialized. Welcome, Administrator.',
        token,
        admin: {
          id: SUPER_ADMIN.id,
          name: SUPER_ADMIN.name,
          username: SUPER_ADMIN.username,
          level: SUPER_ADMIN.level,
          nodeAccess: SUPER_ADMIN.nodeAccess,
        },
        sessionInfo: {
          ip: clientIp,
          userAgent,
          initTime: new Date().toISOString(),
          expiresIn,
          stayVerified: !!stayVerified,
        },
      });
    } catch (err) {
      console.error('[ADMIN AUTH ERROR]', err);
      return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
  }
);

// ── GET /api/admin/verify-session ────────────────────────────────────
// Called on page load to check if existing token is still valid
router.get('/verify-session', requireAdminAuth, (req, res) => {
  return res.json({
    success: true,
    message: 'Session is valid.',
    admin: {
      id: req.admin.id,
      name: req.admin.name,
      username: req.admin.username,
      level: req.admin.level,
      nodeAccess: req.admin.nodeAccess,
    },
    session: {
      issuedAt: new Date(req.admin.iat * 1000).toISOString(),
      expiresAt: new Date(req.admin.exp * 1000).toISOString(),
    },
  });
});

// ── POST /api/admin/logout ───────────────────────────────────────────
router.post('/logout', requireAdminAuth, (req, res) => {
  console.log(`[ADMIN AUTH] 🔓 Super Admin logout: ${req.admin.name} at ${new Date().toISOString()}`);
  // In production: blacklist token via Redis
  return res.json({ success: true, message: 'Session terminated successfully.' });
});

// ── Protected Routes (require auth) ─────────────────────────────────

// GET /api/admin/platform-stats
router.get('/platform-stats', requireAdminAuth, (req, res) => {
  res.json({
    success: true,
    stats: {
      totalCompanies: 148,
      activeRealms: 132,
      trialCompanies: 16,
      totalWorkforce: 12480,
      totalProjects: 3842,
      projectsManaged: '$4.2B',
      platformHealth: '99.98%',
      monthlyRevenue: 284500,
      annualRevenue: 2840000,
      activeSessions: 3842,
      openTickets: 14,
      uptime: process.uptime(),
    },
  });
});

// GET /api/admin/companies
router.get('/companies', requireAdminAuth, (req, res) => {
  res.json({
    success: true,
    companies: [
      { id: 'c001', name: 'Classy Group Construction', plan: 'Enterprise', users: 142, status: 'active', revenue: 42500, health: 90 },
      { id: 'c002', name: 'Vanguard Infrastructure Inc.', plan: 'Pro', users: 89, status: 'active', revenue: 31200, health: 75 },
      { id: 'c003', name: 'Apex Urban Developments', plan: 'Pro', users: 65, status: 'active', revenue: 28900, health: 65 },
      { id: 'c004', name: 'RedBrick Civil Contractors', plan: 'Basic', users: 38, status: 'trial', revenue: 8100, health: 45 },
      { id: 'c005', name: 'Terra Link Construction', plan: 'Basic', users: 22, status: 'expiring', revenue: 4200, health: 30 },
    ],
  });
});

// GET /api/admin/recent-activity
router.get('/recent-activity', requireAdminAuth, (req, res) => {
  res.json({
    success: true,
    activities: [
      { id: 1, type: 'company_created',  title: 'New Company Created',       desc: 'Vanguard Infrastructure Inc. — 45 Employees activated.',       time: '2 min ago',  color: 'blue' },
      { id: 2, type: 'license_renewed',  title: 'Company License Renewed',   desc: 'Classy Group Construction — Enterprise Plan renewed 12 months.',time: '34 min ago', color: 'green' },
      { id: 3, type: 'expiry_warning',   title: 'License Expiry Warning',    desc: 'BuildRight Solutions — License expiring in 3 days.',           time: '2 hrs ago',  color: 'orange' },
      { id: 4, type: 'support_ticket',   title: 'New Support Ticket',        desc: '#T-937: Payroll module not generating salary slips correctly.', time: '3 hrs ago',  color: 'red' },
      { id: 5, type: 'plan_upgraded',    title: 'Plan Upgraded',             desc: 'Apex Urban Developments — Basic → Pro migration completed.',    time: '5 hrs ago',  color: 'purple' },
    ],
  });
});

// GET /api/admin/support-tickets
router.get('/support-tickets', requireAdminAuth, (req, res) => {
  res.json({
    success: true,
    breakdown: [
      { label: 'Critical',      icon: '🔴', count: 4 },
      { label: 'High Priority', icon: '🟠', count: 5 },
      { label: 'Normal',        icon: '🟡', count: 4 },
      { label: 'Maintenance',   icon: '🔵', count: 2 },
    ],
    total: 14,
  });
});

module.exports = router;

