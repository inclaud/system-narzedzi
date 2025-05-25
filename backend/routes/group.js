// Trasy do zarządzania grupami użytkowników
// Obsługuje tworzenie grup, przypisywanie użytkowników, zarządzanie administratorami grup

const express = require('express');
const { body, validationResult, param, query } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { requireAuth, requireSuperAdmin, requireGroupAdmin } = require('../config/passport');

const router = express.Router();
const prisma = new PrismaClient();

// ==================== POBIERANIE LISTY GRUP ====================

// Endpoint do pobierania wszystkich grup (różne uprawnienia dają różne dane)
router.get('/', requireAuth, [
  query('includeInactive').optional().isBoolean().withMessage('includeInactive musi być true/false')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const includeInactive = req.query.includeInactive === 'true';
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Warunki filtrowania
    const whereConditions = {};

    // Tylko superadmin może zobaczyć nieaktywne grupy
    if (!includeInactive || !isSuperAdmin) {
      whereConditions.isActive = true;
    }

    let groups;

    if (isSuperAdmin) {
      // Superadmin widzi wszystkie grupy z pełnymi statystykami
      groups = await prisma.group.findMany({
        where: whereConditions,
        include: {
          _count: {
            select: {
              userGroups: true, // Liczba użytkowników w grupie
              groupAdmins: true, // Liczba administratorów grupy
              groupTools: true // Liczba narzędzi dostępnych dla grupy
            }
          },
          groupAdmins: {
            include: {
              user: {
                select: {
                  id: true,
                  firstName: true,
                  lastName: true,
                  email: true
                }
              }
            }
          }
        },
        orderBy: {
          name: 'asc'
        }
      });
    } else {
      // Zwykły użytkownik widzi tylko grupy, do których należy lub którymi administruje
      const userGroupIds = await prisma.userGroup.findMany({
        where: { userId: req.user.id },
        select: { groupId: true }
      });

      const adminGroupIds = await prisma.groupAdmin.findMany({
        where: { userId: req.user.id },
        select: { groupId: true }
      });

      const accessibleGroupIds = [
        ...userGroupIds.map(ug => ug.groupId),
        ...adminGroupIds.map(ag => ag.groupId)
      ];

      if (accessibleGroupIds.length === 0) {
        return res.json({ groups: [] });
      }

      groups = await prisma.group.findMany({
        where: {
          ...whereConditions,
          id: { in: accessibleGroupIds }
        },
        include: {
          _count: {
            select: {
              userGroups: true,
              groupTools: true
            }
          }
        },
        orderBy: {
          name: 'asc'
        }
      });
    }

    // Formatowanie odpowiedzi
    const formattedGroups = groups.map(group => ({
      id: group.id,
      name: group.name,
      description: group.description,
      color: group.color,
      isActive: group.isActive,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
      userCount: group._count.userGroups,
      toolCount: group._count.groupTools,
      adminCount: group._count?.groupAdmins || 0,
      admins: group.groupAdmins?.map(ga => ga.user) || []
    }));

    res.json({ groups: formattedGroups });

  } catch (error) {
    console.error('Błąd podczas pobierania grup:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania grup'
    });
  }
});

// ==================== POBIERANIE SZCZEGÓŁÓW GRUPY ====================

router.get('/:id', requireAuth, [
  param('id').isInt().withMessage('ID grupy musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Sprawdzamy uprawnienia dostępu do grupy
    if (!isSuperAdmin) {
      const hasAccess = await prisma.$queryRaw`
        SELECT 1 FROM (
          SELECT group_id FROM user_groups WHERE user_id = ${req.user.id} AND group_id = ${groupId}
          UNION
          SELECT group_id FROM group_admins WHERE user_id = ${req.user.id} AND group_id = ${groupId}
        ) AS access_check
        LIMIT 1
      `;

      if (!hasAccess.length) {
        return res.status(403).json({
          error: 'Brak dostępu do tej grupy'
        });
      }
    }

    // Pobieramy szczegółowe informacje o grupie
    const group = await prisma.group.findUnique({
      where: { id: groupId },
      include: {
        userGroups: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                accountType: true,
                isActive: true
              }
            }
          },
          orderBy: {
            addedAt: 'desc'
          }
        },
        groupAdmins: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true
              }
            }
          }
        },
        groupTools: {
          include: {
            tool: {
              select: {
                id: true,
                name: true,
                description: true,
                icon: true,
                category: true,
                isActive: true
              }
            }
          }
        }
      }
    });

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    // Sprawdzamy czy użytkownik jest administratorem tej grupy
    const isGroupAdmin = group.groupAdmins.some(ga => ga.userId === req.user.id);

    // Formatujemy odpowiedź
    const formattedGroup = {
      id: group.id,
      name: group.name,
      description: group.description,
      color: group.color,
      isActive: group.isActive,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
      users: group.userGroups.map(ug => ({
        ...ug.user,
        addedAt: ug.addedAt,
        addedBy: ug.addedBy
      })),
      admins: group.groupAdmins.map(ga => ({
        ...ga.user,
        permissions: {
          canAddUsers: ga.canAddUsers,
          canEditUsers: ga.canEditUsers,
          canRemoveUsers: ga.canRemoveUsers,
          canManageUsers: ga.canManageUsers,
          canViewReports: ga.canViewReports
        }
      })),
      tools: group.groupTools.map(gt => ({
        ...gt.tool,
        accessLevel: gt.accessLevel,
        grantedAt: gt.createdAt
      })),
      permissions: {
        canEdit: isSuperAdmin || isGroupAdmin,
        canManageUsers: isSuperAdmin || isGroupAdmin,
        canManageTools: isSuperAdmin,
        canDelete: isSuperAdmin
      }
    };

    res.json({ group: formattedGroup });

  } catch (error) {
    console.error('Błąd podczas pobierania grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania grupy'
    });
  }
});

// ==================== TWORZENIE NOWEJ GRUPY ====================

const createGroupValidators = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Nazwa grupy musi mieć od 2 do 100 znaków'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Opis może mieć maksymalnie 500 znaków'),
  
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Kolor musi być w formacie hex (#RRGGBB)')
];

router.post('/', requireSuperAdmin, createGroupValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const { name, description, color } = req.body;

    // Sprawdzamy czy grupa o takiej nazwie już istnieje
    const existingGroup = await prisma.group.findFirst({
      where: { name: name.trim() }
    });

    if (existingGroup) {
      return res.status(400).json({
        error: 'Grupa o takiej nazwie już istnieje'
      });
    }

    // Tworzymy nową grupę
    const newGroup = await prisma.group.create({
      data: {
        name: name.trim(),
        description: description?.trim() || null,
        color: color || null,
        isActive: true
      }
    });

    res.status(201).json({
      message: 'Grupa została utworzona pomyślnie',
      group: newGroup
    });

  } catch (error) {
    console.error('Błąd podczas tworzenia grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas tworzenia grupy'
    });
  }
});

// ==================== AKTUALIZACJA GRUPY ====================

const updateGroupValidators = [
  param('id').isInt().withMessage('ID grupy musi być liczbą'),
  
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Nazwa grupy musi mieć od 2 do 100 znaków'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Opis może mieć maksymalnie 500 znaków'),
  
  body('color')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Kolor musi być w formacie hex (#RRGGBB)'),
  
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive musi być true lub false')
];

router.put('/:id', requireAuth, updateGroupValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const { name, description, color, isActive } = req.body;
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Sprawdzamy uprawnienia - superadmin lub admin grupy
    if (!isSuperAdmin) {
      const groupAdmin = await prisma.groupAdmin.findFirst({
        where: {
          userId: req.user.id,
          groupId: groupId
        }
      });

      if (!groupAdmin) {
        return res.status(403).json({
          error: 'Brak uprawnień do edycji tej grupy'
        });
      }
    }

    // Sprawdzamy czy grupa istnieje
    const existingGroup = await prisma.group.findUnique({
      where: { id: groupId }
    });

    if (!existingGroup) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    // Sprawdzamy unikalność nazwy jeśli jest zmieniana
    if (name && name.trim() !== existingGroup.name) {
      const nameConflict = await prisma.group.findFirst({
        where: { 
          name: name.trim(),
          id: { not: groupId }
        }
      });

      if (nameConflict) {
        return res.status(400).json({
          error: 'Grupa o takiej nazwie już istnieje'
        });
      }
    }

    // Przygotowujemy dane do aktualizacji
    const updateData = {};
    if (name !== undefined) updateData.name = name.trim();
    if (description !== undefined) updateData.description = description?.trim() || null;
    if (color !== undefined) updateData.color = color || null;
    
    // Tylko superadmin może zmieniać status aktywności
    if (isActive !== undefined && isSuperAdmin) {
      updateData.isActive = isActive;
    }

    // Aktualizujemy grupę
    const updatedGroup = await prisma.group.update({
      where: { id: groupId },
      data: updateData,
      include: {
        _count: {
          select: {
            userGroups: true,
            groupAdmins: true,
            groupTools: true
          }
        }
      }
    });

    res.json({
      message: 'Grupa została zaktualizowana',
      group: {
        ...updatedGroup,
        userCount: updatedGroup._count.userGroups,
        adminCount: updatedGroup._count.groupAdmins,
        toolCount: updatedGroup._count.groupTools,
        _count: undefined
      }
    });

  } catch (error) {
    console.error('Błąd podczas aktualizacji grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas aktualizacji grupy'
    });
  }
});

// ==================== USUWANIE GRUPY ====================

router.delete('/:id', requireSuperAdmin, [
  param('id').isInt().withMessage('ID grupy musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);

    // Sprawdzamy czy grupa istnieje
    const group = await prisma.group.findUnique({
      where: { id: groupId },
      include: {
        _count: {
          select: {
            userGroups: true,
            groupAdmins: true
          }
        }
      }
    });

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    // Sprawdzamy czy grupa ma użytkowników (opcjonalne ostrzeżenie)
    if (group._count.userGroups > 0) {
      // Możemy wymagać potwierdzenia lub automatycznie przenosić użytkowników
      // Na razie pozwalamy na usunięcie (Cascade automatycznie usuwa powiązania)
    }

    // Usuwamy grupę
    await prisma.group.delete({
      where: { id: groupId }
    });

    res.json({
      message: 'Grupa została usunięta',
      deletedGroup: {
        id: group.id,
        name: group.name,
        userCount: group._count.userGroups,
        adminCount: group._count.groupAdmins
      }
    });

  } catch (error) {
    console.error('Błąd podczas usuwania grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania grupy'
    });
  }
});

// ==================== ZARZĄDZANIE UŻYTKOWNIKAMI W GRUPIE ====================

// Dodawanie użytkownika do grupy
const addUserValidators = [
  param('id').isInt().withMessage('ID grupy musi być liczbą'),
  body('userId').isInt().withMessage('ID użytkownika musi być liczbą')
];

router.post('/:id/users', requireAuth, addUserValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const { userId } = req.body;
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Sprawdzamy uprawnienia
    if (!isSuperAdmin) {
      const groupAdmin = await prisma.groupAdmin.findFirst({
        where: {
          userId: req.user.id,
          groupId: groupId,
          canAddUsers: true // Musi mieć uprawnienie do dodawania
        }
      });

      if (!groupAdmin) {
        return res.status(403).json({
          error: 'Brak uprawnień do dodawania użytkowników do tej grupy'
        });
      }
    }

    // Sprawdzamy czy grupa i użytkownik istnieją
    const [group, user] = await Promise.all([
      prisma.group.findUnique({ where: { id: groupId } }),
      prisma.user.findUnique({ where: { id: userId } })
    ]);

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    if (!user) {
      return res.status(404).json({
        error: 'Użytkownik nie został znaleziony'
      });
    }

    if (!user.isActive) {
      return res.status(400).json({
        error: 'Nie można dodać nieaktywnego użytkownika do grupy'
      });
    }

    // Sprawdzamy czy użytkownik już jest w grupie
    const existingMembership = await prisma.userGroup.findFirst({
      where: {
        userId: userId,
        groupId: groupId
      }
    });

    if (existingMembership) {
      return res.status(400).json({
        error: 'Użytkownik już należy do tej grupy'
      });
    }

    // Dodajemy użytkownika do grupy
    const userGroup = await prisma.userGroup.create({
      data: {
        userId: userId,
        groupId: groupId,
        addedBy: req.user.id
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Użytkownik został dodany do grupy',
      membership: {
        user: userGroup.user,
        addedAt: userGroup.addedAt,
        addedBy: userGroup.addedBy
      }
    });

  } catch (error) {
    console.error('Błąd podczas dodawania użytkownika do grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas dodawania użytkownika do grupy'
    });
  }
});

// Usuwanie użytkownika z grupy
router.delete('/:id/users/:userId', requireAuth, [
  param('id').isInt().withMessage('ID grupy musi być liczbą'),
  param('userId').isInt().withMessage('ID użytkownika musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const userId = parseInt(req.params.userId);
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Sprawdzamy uprawnienia
    if (!isSuperAdmin && req.user.id !== userId) {
      const groupAdmin = await prisma.groupAdmin.findFirst({
        where: {
          userId: req.user.id,
          groupId: groupId,
          canRemoveUsers: true
        }
      });

      if (!groupAdmin) {
        return res.status(403).json({
          error: 'Brak uprawnień do usuwania użytkowników z tej grupy'
        });
      }
    }

    // Sprawdzamy czy przypisanie istnieje
    const userGroup = await prisma.userGroup.findFirst({
      where: {
        userId: userId,
        groupId: groupId
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    if (!userGroup) {
      return res.status(404).json({
        error: 'Użytkownik nie należy do tej grupy'
      });
    }

    // Usuwamy użytkownika z grupy
    await prisma.userGroup.delete({
      where: {
        id: userGroup.id
      }
    });

    res.json({
      message: 'Użytkownik został usunięty z grupy',
      removedUser: userGroup.user
    });

  } catch (error) {
    console.error('Błąd podczas usuwania użytkownika z grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania użytkownika z grupy'
    });
  }
});

// ==================== ZARZĄDZANIE ADMINISTRATORAMI GRUP ====================

// Dodawanie administratora grupy
const addAdminValidators = [
  param('id').isInt().withMessage('ID grupy musi być liczbą'),
  body('userId').isInt().withMessage('ID użytkownika musi być liczbą'),
  body('permissions').optional().isObject().withMessage('Uprawnienia muszą być obiektem')
];

router.post('/:id/admins', requireSuperAdmin, addAdminValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const { userId, permissions = {} } = req.body;

    // Domyślne uprawnienia
    const defaultPermissions = {
      canAddUsers: true,
      canEditUsers: true,
      canRemoveUsers: true,
      canManageUsers: true,
      canViewReports: false
    };

    const finalPermissions = { ...defaultPermissions, ...permissions };

    // Sprawdzamy czy grupa i użytkownik istnieją
    const [group, user] = await Promise.all([
      prisma.group.findUnique({ where: { id: groupId } }),
      prisma.user.findUnique({ where: { id: userId } })
    ]);

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    if (!user) {
      return res.status(404).json({
        error: 'Użytkownik nie został znaleziony'
      });
    }

    // Sprawdzamy czy użytkownik już jest administratorem
    const existingAdmin = await prisma.groupAdmin.findFirst({
      where: {
        userId: userId,
        groupId: groupId
      }
    });

    if (existingAdmin) {
      return res.status(400).json({
        error: 'Użytkownik już jest administratorem tej grupy'
      });
    }

    // Dodajemy jako administratora
    const groupAdmin = await prisma.groupAdmin.create({
      data: {
        userId: userId,
        groupId: groupId,
        ...finalPermissions
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Administrator grupy został dodany',
      admin: {
        user: groupAdmin.user,
        permissions: {
          canAddUsers: groupAdmin.canAddUsers,
          canEditUsers: groupAdmin.canEditUsers,
          canRemoveUsers: groupAdmin.canRemoveUsers,
          canManageUsers: groupAdmin.canManageUsers,
          canViewReports: groupAdmin.canViewReports
        },
        createdAt: groupAdmin.createdAt
      }
    });

  } catch (error) {
    console.error('Błąd podczas dodawania administratora grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas dodawania administratora grupy'
    });
  }
});

// Usuwanie administratora grupy
router.delete('/:id/admins/:userId', requireSuperAdmin, [
  param('id').isInt().withMessage('ID grupy musi być liczbą'),
  param('userId').isInt().withMessage('ID użytkownika musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const groupId = parseInt(req.params.id);
    const userId = parseInt(req.params.userId);

    // Sprawdzamy czy administrator istnieje
    const groupAdmin = await prisma.groupAdmin.findFirst({
      where: {
        userId: userId,
        groupId: groupId
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    if (!groupAdmin) {
      return res.status(404).json({
        error: 'Użytkownik nie jest administratorem tej grupy'
      });
    }

    // Usuwamy administratora
    await prisma.groupAdmin.delete({
      where: {
        id: groupAdmin.id
      }
    });

    res.json({
      message: 'Administrator grupy został usunięty',
      removedAdmin: groupAdmin.user
    });

  } catch (error) {
    console.error('Błąd podczas usuwania administratora grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania administratora grupy'
    });
  }
});

module.exports = router;
