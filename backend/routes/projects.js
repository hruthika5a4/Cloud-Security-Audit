const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');

const router = express.Router();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-local-key-for-jwt';

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

router.use(authenticateToken);

// =======================
// PROJECTS API
// =======================

// Create a new Project
router.post('/', async (req, res) => {
  try {
    const { name, provider } = req.body;
    
    if (!name || !provider) {
      return res.status(400).json({ error: 'Project name and provider are required.' });
    }

    const project = await prisma.project.create({
      data: {
        name,
        provider,
        userId: req.user.userId
      }
    });

    res.status(201).json(project);
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Failed to create project.' });
  }
});

// Get all Projects for the current logged-in user
router.get('/', async (req, res) => {
  try {
    const projects = await prisma.project.findMany({
      where: { userId: req.user.userId },
      include: {
        _count: {
          select: { scans: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects.' });
  }
});

// Get all Projects for the current logged-in user (Simplified for lists)
router.get('/all', async (req, res) => {
  try {
    const projects = await prisma.project.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch project list.' });
  }
});

// Get a single Project by ID
router.get('/:id', async (req, res) => {
  try {
    const project = await prisma.project.findUnique({
      where: { id: req.params.id },
      include: {
        _count: {
          select: { scans: true }
        }
      }
    });

    if (!project || project.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Project not found or access denied.' });
    }

    res.json(project);
  } catch (error) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: 'Failed to fetch project.' });
  }
});

// =======================
// SCAN HISTORY API
// =======================

// Get all scans for a Specific Project
router.get('/:projectId/scans', async (req, res) => {
  try {
    const { projectId } = req.params;

    let scans = [];

    if (projectId === 'all') {
      scans = await prisma.scanHistory.findMany({
        where: { project: { userId: req.user.userId } },
        include: { project: true },
        orderBy: { createdAt: 'desc' }
      });
    } else {
      const project = await prisma.project.findUnique({ where: { id: projectId } });
      if (!project || project.userId !== req.user.userId) {
        return res.status(404).json({ error: 'Project not found or access denied.' });
      }

      scans = await prisma.scanHistory.findMany({
        where: { projectId: projectId },
        include: { project: true },
        orderBy: { createdAt: 'desc' }
      });
    }

    const formattedScans = scans.map(scan => ({
      ...scan,
      findings: JSON.parse(scan.findings)
    }));

    res.json(formattedScans);
  } catch (error) {
    console.error('Error fetching scan history:', error);
    res.status(500).json({ error: 'Failed to fetch scan history.' });
  }
});

module.exports = router;
