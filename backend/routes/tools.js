// Trasy do zarządzania narzędziami - CRUD operacje, przypisywanie do grup
// Obsługuje katalog narzędzi dostępnych dla użytkowników

const express = require('express');
const { body, validationResult, param, query } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { requireAuth, requireSuperAdmin } = require('../config/passport');

const router = express.Router();
const prisma = new PrismaClient();

// ==================== POBIERANIE NARZĘDZI DLA UŻYTKOWNIKA ====================

// Endpoint zwracający narzędzia dostępne dla zalogowanego użytkownika
router.get('/my-tools', requireAuth, async (req, res) => {
  try {
    // Pobieramy grupy użytkownika
    const userGroups = await prisma.userGroup.findMany({
      where: {
        userId: req.user.id,
        group: {
          isActive: true // Tylko aktywne grupy
        }
      },
      select: {
        groupId: true
      }
    });

    const groupIds = userGroups.map(ug => ug.groupId);

    if (groupIds.length === 0) {
      return res.json({ tools: [] });
    }

    // Pobieramy narzędzia dostępne dla grup użytkownika
    const availableTools = await prisma.groupTool.findMany({
      where: {
        groupId: { in: groupIds },
        tool: {
          isActive: true // Tylko aktywne narzędzia
        }
      },
      include: {
        tool: true,
        group: {
          select: {
            id: true,
            name: true,
            color: true
          }
        }
      },
      orderBy: {
        tool: {
          name: 'asc'
        }
      }
    });

    // Grupujemy narzędzia według kategorii i usuwamy duplikaty
    const toolsMap = new Map();
    
    availableTools.forEach(gt => {
      const toolId = gt.tool.id;
      
      if (!toolsMap.has(toolId)) {
        toolsMap.set(toolId, {
          id: gt.tool.id,
          name: gt.tool.name,
          description: gt.tool.description,
          url: gt.tool.url,
          icon: gt.tool.icon,
          category: gt.tool.category,
          isExternal: gt.tool.isExternal,
          accessLevel: gt.accessLevel,
          groups: [gt.group]
        });
      } else {
        // Narzędzie już istnieje - dodajemy grupę i wybieramy wyższy poziom dostępu
        const existingTool = toolsMap.get(toolId);
        existingTool.groups.push(gt.group);
        
        // "write" ma wyższy priorytet niż "read"
        if (gt.accessLevel === 'write' && existingTool.accessLevel === 'read') {
          existingTool.accessLevel = 'write';
        }
      }
    });

    const tools = Array.from(toolsMap.values());

    // Grupujemy według kategorii
    const toolsByCategory = tools.reduce((acc, tool) => {
      const category = tool.category || 'Bez kategorii';
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(tool);
      return acc;
    }, {});

    res.json({
      tools: tools,
      toolsByCategory: toolsByCategory,
      totalCount: tools.length
    });

  } catch (error) {
    console.error('Błąd podczas pobierania narzędzi użytkownika:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania narzędzi'
    });
  }
});

// ==================== POBIERANIE WSZYSTKICH NARZĘDZI (ADMIN) ====================

router.get('/', requireSuperAdmin, [
  query('page').optional().isInt({ min: 1 }).withMessage('Numer strony musi być liczbą większą od 0'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit musi być liczbą od 1 do 100'),
  query('search').optional().isLength({ max: 100 }).withMessage('Wyszukiwanie max 100 znaków'),
  query('category').optional().isLength({ max: 50 }).withMessage('Kategoria max 50 znaków'),
  query('active').optional().isBoolean().withMessage('Active musi być true/false')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search;
    const category = req.query.category;
    const activeFilter = req.query.active !== undefined ? req.query.active === 'true' : null;

    // Budowanie warunków wyszukiwania
    const whereConditions = {};

    if (activeFilter !== null) {
      whereConditions.isActive = activeFilter;
    }

    if (search) {
      whereConditions.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } }
      ];
    }

    if (category) {
      whereConditions.category = category;
    }

    // Pobieranie narzędzi z paginacją
    const [tools, totalCount] = await Promise.all([
      prisma.tool.findMany({
        where: whereConditions,
        include: {
          _count: {
            select: {
              groupTools: true // Liczba grup mających dostęp
            }
          },
          groupTools: {
            include: {
              group: {
                select: {
                  id: true,
                  name: true,
                  color: true
                }
              }
            }
          }
        },
        skip: skip,
        take: limit,
        orderBy: {
          name: 'asc'
        }
      }),
      prisma.tool.count({ where: whereConditions })
    ]);

    // Pobieramy wszystkie dostępne kategorie
    const categories = await prisma.tool.findMany({
      where: { isActive: true },
      select: { category: true },
      distinct: ['category']
    });

    const formattedTools = tools.map(tool => ({
      ...tool,
      groupCount: tool._count.groupTools,
      groups: tool.groupTools.map(gt => gt.group),
      _count: undefined,
      groupTools: undefined
    }));

    res.json({
      tools: formattedTools,
      categories: categories.map(c => c.category).filter(Boolean),
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalCount / limit),
        totalTools: totalCount,
        toolsPerPage: limit,
        hasNextPage: page < Math.ceil(totalCount / limit),
        hasPrevPage: page > 1
      }
    });

  } catch (error) {
    console.error('Błąd podczas pobierania narzędzi:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania narzędzi'
    });
  }
});

// ==================== POBIERANIE SZCZEGÓŁÓW NARZĘDZIA ====================

router.get('/:id', requireAuth, [
  param('id').isInt().withMessage('ID narzędzia musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const toolId = parseInt(req.params.id);
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Pobieramy narzędzie
    const tool = await prisma.tool.findUnique({
      where: { id: toolId },
      include: {
        groupTools: {
          include: {
            group: {
              select: {
                id: true,
                name: true,
                color: true
              }
            }
          }
        }
      }
    });

    if (!tool) {
      return res.status(404).json({
        error: 'Narzędzie nie zostało znalezione'
      });
    }

    // Sprawdzamy czy użytkownik ma dostęp (jeśli nie jest superadminem)
    if (!isSuperAdmin) {
      const userGroups = await prisma.userGroup.findMany({
        where: {
          userId: req.user.id,
          groupId: {
            in: tool.groupTools.map(gt => gt.groupId)
          }
        }
      });

      if (userGroups.length === 0) {
        return res.status(403).json({
          error: 'Brak dostępu do tego narzędzia'
        });
      }

      // Logujemy dostęp do narzędzia
      await prisma.toolAccess.create({
        data: {
          userId: req.user.id,
          toolId: toolId,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent')
        }
      });
    }

    const formattedTool = {
      ...tool,
      groups: tool.groupTools.map(gt => ({
        ...gt.group,
        accessLevel: gt.accessLevel
      })),
      groupTools: undefined
    };

    res.json({ tool: formattedTool });

  } catch (error) {
    console.error('Błąd podczas pobierania narzędzia:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania narzędzia'
    });
  }
});

// ==================== TWORZENIE NOWEGO NARZĘDZIA ====================

const createToolValidators = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Nazwa narzędzia musi mieć od 2 do 100 znaków'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Opis może mieć maksymalnie 500 znaków'),
  
  body('url')
    .isURL({ require_protocol: true })
    .withMessage('URL musi być prawidłowym adresem'),
  
  body('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Kategoria może mieć maksymalnie 50 znaków'),
  
  body('icon')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Ścieżka ikony może mieć maksymalnie 200 znaków'),
  
  body('isExternal')
    .optional()
    .isBoolean()
    .withMessage('isExternal musi być true lub false')
];

router.post('/', requireSuperAdmin, createToolValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const { name, description, url, category, icon, isExternal } = req.body;

    // Sprawdzamy czy narzędzie o takiej nazwie już istnieje
    const existingTool = await prisma.tool.findFirst({
      where: { name: name.trim() }
    });

    if (existingTool) {
      return res.status(400).json({
        error: 'Narzędzie o takiej nazwie już istnieje'
      });
    }

    // Tworzymy nowe narzędzie
    const newTool = await prisma.tool.create({
      data: {
        name: name.trim(),
        description: description?.trim() || null,
        url: url.trim(),
        category: category?.trim() || null,
        icon: icon?.trim() || null,
        isExternal: isExternal || false,
        isActive: true
      }
    });

    res.status(201).json({
      message: 'Narzędzie zostało utworzone pomyślnie',
      tool: newTool
    });

  } catch (error) {
    console.error('Błąd podczas tworzenia narzędzia:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas tworzenia narzędzia'
    });
  }
});

// ==================== AKTUALIZACJA NARZĘDZIA ====================

const updateToolValidators = [
  param('id').isInt().withMessage('ID narzędzia musi być liczbą'),
  
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Nazwa narzędzia musi mieć od 2 do 100 znaków'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Opis może mieć maksymalnie 500 znaków'),
  
  body('url')
    .optional()
    .isURL({ require_protocol: true })
    .withMessage('URL musi być prawidłowym adresem'),
  
  body('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Kategoria może mieć maksymalnie 50 znaków'),
  
  body('icon')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Ścieżka ikony może mieć maksymalnie 200 znaków'),
  
  body('isExternal')
    .optional()
    .isBoolean()
    .withMessage('isExternal musi być true lub false'),
  
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive musi być true lub false')
];

router.put('/:id', requireSuperAdmin, updateToolValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const toolId = parseInt(req.params.id);
    const { name, description, url, category, icon, isExternal, isActive } = req.body;

    // Sprawdzamy czy narzędzie istnieje
    const existingTool = await prisma.tool.findUnique({
      where: { id: toolId }
    });

    if (!existingTool) {
      return res.status(404).json({
        error: 'Narzędzie nie zostało znalezione'
      });
    }

    // Sprawdzamy unikalność nazwy jeśli jest zmieniana
    if (name && name.trim() !== existingTool.name) {
      const nameConflict = await prisma.tool.findFirst({
        where: { 
          name: name.trim(),
          id: { not: toolId }
        }
      });

      if (nameConflict) {
        return res.status(400).json({
          error: 'Narzędzie o takiej nazwie już istnieje'
        });
      }
    }

    // Przygotowujemy dane do aktualizacji
    const updateData = {};
    if (name !== undefined) updateData.name = name.trim();
    if (description !== undefined) updateData.description = description?.trim() || null;
    if (url !== undefined) updateData.url = url.trim();
    if (category !== undefined) updateData.category = category?.trim() || null;
    if (icon !== undefined) updateData.icon = icon?.trim() || null;
    if (isExternal !== undefined) updateData.isExternal = isExternal;
    if (isActive !== undefined) updateData.isActive = isActive;

    // Aktualizujemy narzędzie
    const updatedTool = await prisma.tool.update({
      where: { id: toolId },
      data: updateData,
      include: {
        _count: {
          select: {
            groupTools: true
          }
        }
      }
    });

    res.json({
      message: 'Narzędzie zostało zaktualizowane',
      tool: {
        ...updatedTool,
        groupCount: updatedTool._count.groupTools,
        _count: undefined
      }
    });

  } catch (error) {
    console.error('Błąd podczas aktualizacji narzędzia:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas aktualizacji narzędzia'
    });
  }
});

// ==================== USUWANIE NARZĘDZIA ====================

router.delete('/:id', requireSuperAdmin, [
  param('id').isInt().withMessage('ID narzędzia musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const toolId = parseInt(req.params.id);

    // Sprawdzamy czy narzędzie istnieje
    const tool = await prisma.tool.findUnique({
      where: { id: toolId },
      include: {
        _count: {
          select: {
            groupTools: true
          }
        }
      }
    });

    if (!tool) {
      return res.status(404).json({
        error: 'Narzędzie nie zostało znalezione'
      });
    }

    // Usuwamy narzędzie (Cascade automatycznie usuwa powiązania)
    await prisma.tool.delete({
      where: { id: toolId }
    });

    res.json({
      message: 'Narzędzie zostało usunięte',
      deletedTool: {
        id: tool.id,
        name: tool.name,
        groupCount: tool._count.groupTools
      }
    });

  } catch (error) {
    console.error('Błąd podczas usuwania narzędzia:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania narzędzia'
    });
  }
});

// ==================== PRZYPISYWANIE NARZĘDZIA DO GRUPY ====================

const assignToolValidators = [
  param('id').isInt().withMessage('ID narzędzia musi być liczbą'),
  body('groupId').isInt().withMessage('ID grupy musi być liczbą'),
  body('accessLevel').isIn(['read', 'write']).withMessage('Poziom dostępu musi być "read" lub "write"')
];

router.post('/:id/assign-group', requireSuperAdmin, assignToolValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const toolId = parseInt(req.params.id);
    const { groupId, accessLevel } = req.body;

    // Sprawdzamy czy narzędzie i grupa istnieją
    const [tool, group] = await Promise.all([
      prisma.tool.findUnique({ where: { id: toolId } }),
      prisma.group.findUnique({ where: { id: groupId } })
    ]);

    if (!tool) {
      return res.status(404).json({
        error: 'Narzędzie nie zostało znalezione'
      });
    }

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    // Sprawdzamy czy przypisanie już istnieje
    const existingAssignment = await prisma.groupTool.findFirst({
      where: {
        groupId: groupId,
        toolId: toolId
      }
    });

    if (existingAssignment) {
      // Aktualizujemy poziom dostępu
      const updatedAssignment = await prisma.groupTool.update({
        where: { id: existingAssignment.id },
        data: { accessLevel: accessLevel }
      });

      return res.json({
        message: 'Poziom dostępu został zaktualizowany',
        assignment: updatedAssignment
      });
    }

    // Tworzymy nowe przypisanie
    const assignment = await prisma.groupTool.create({
      data: {
        groupId: groupId,
        toolId: toolId,
        accessLevel: accessLevel
      },
      include: {
        group: {
          select: {
            id: true,
            name: true,
            color: true
          }
        },
        tool: {
          select: {
            id: true,
            name: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Narzędzie zostało przypisane do grupy',
      assignment: assignment
    });

  } catch (error) {
    console.error('Błąd podczas przypisywania narzędzia do grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas przypisywania narzędzia do grupy'
    });
  }
});

// ==================== USUWANIE PRZYPISANIA NARZĘDZIA DO GRUPY ====================

router.delete('/:id/assign-group/:groupId', requireSuperAdmin, [
  param('id').isInt().withMessage('ID narzędzia musi być liczbą'),
  param('groupId').isInt().withMessage('ID grupy musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const toolId = parseInt(req.params.id);
    const groupId = parseInt(req.params.groupId);

    // Sprawdzamy czy przypisanie istnieje
    const assignment = await prisma.groupTool.findFirst({
      where: {
        groupId: groupId,
        toolId: toolId
      }
    });

    if (!assignment) {
      return res.status(404).json({
        error: 'Przypisanie nie zostało znalezione'
      });
    }

    // Usuwamy przypisanie
    await prisma.groupTool.delete({
      where: { id: assignment.id }
    });

    res.json({
      message: 'Przypisanie narzędzia do grupy zostało usunięte'
    });

  } catch (error) {
    console.error('Błąd podczas usuwania przypisania:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania przypisania'
    });
  }
});

module.exports = router;
