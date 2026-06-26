const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// ── Mock super admins DB (replace with real DB later) ────────────────
const SUPER_ADMINS = [
  {
    id: 'sa001',
    email: 'superadmin@constructerp.com',
    passwordHash: bcrypt.hashSync('SuperAdmin@123', 10),
    name: 'System Administrator',
    level: 'GLOBAL',
    nodeAccess: 'ALL',
    ipWhitelist: [],
  },
  {
    id: 'sa002',
    email: 'admin@apexbuild.com',
    passwordHash: bcrypt.hashSync('ApexAdmin2024', 10),
    name: 'Apex Build Admin',
    level: 'ENTERPRISE',
    nodeAccess: 'APEXBUILD',
    ipWhitelist: [],
  },
];

// ── POST /api/admin/login ────────────────────────────────────────────
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid administrator email is required.'),
    body('password').isLength({ min: 6 }).withMessage('Access key must be at least 6 characters.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, errors: errors.array() });
    }

    const { email, password, stayVerified } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
      const admin = SUPER_ADMINS.find(
        (a) => a.email.toLowerCase() === email.toLowerCase()
      );

      if (!admin) {
        console.warn(`[ADMIN SECURITY] Failed login attempt for email: ${email} from IP: ${clientIp}`);
        return res.status(401).json({
          success: false,
          message: 'Access denied. Unauthorized administrator credentials.',
          logged: true,
        });
      }

      const isMatch = await bcrypt.compare(password, admin.passwordHash);
      if (!isMatch) {
        console.warn(`[ADMIN SECURITY] Wrong password for admin: ${email} from IP: ${clientIp}`);
        return res.status(401).json({
          success: false,
          message: 'Access denied. Invalid access key. This attempt has been logged.',
          logged: true,
        });
      }

      // Generate privileged JWT
      const token = jwt.sign(
        {
          id: admin.id,
          role: 'super_admin',
          level: admin.level,
          nodeAccess: admin.nodeAccess,
          email: admin.email,
          name: admin.name,
        },
        process.env.JWT_SECRET,
        { expiresIn: stayVerified ? '24h' : '4h' }
      );

      console.log(`[ADMIN AUTH] Super Admin login: ${admin.name} (${admin.email}) from IP: ${clientIp} at ${new Date().toISOString()}`);

      return res.json({
        success: true,
        message: 'Safe session initialized. Welcome, Administrator.',
        token,
        admin: {
          id: admin.id,
          name: admin.name,
          email: admin.email,
          level: admin.level,
          nodeAccess: admin.nodeAccess,
        },
        sessionInfo: {
          ip: clientIp,
          initTime: new Date().toISOString(),
          expiresIn: stayVerified ? '24h' : '4h',
        },
      });
    } catch (err) {
      console.error('[ADMIN AUTH ERROR]', err);
      return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
  }
);

// ── GET /api/admin/platform-stats ────────────────────────────────
router.get('/platform-stats', (req, res) => {
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

// ── GET /api/admin/companies ──────────────────────────────────────
router.get('/companies', (req, res) => {
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

// ── GET /api/admin/recent-activity ───────────────────────────────
router.get('/recent-activity', (req, res) => {
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

// ── GET /api/admin/support-tickets ───────────────────────────────
router.get('/support-tickets', (req, res) => {
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
