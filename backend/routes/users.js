// Trasy do zarządzania użytkownikami - CRUD operacje, przypisywanie do grup
// Obsługuje różne poziomy uprawnień: superadmin, admin grupy, zwykły użytkownik

const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult, param, query } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { requireAuth, requireSuperAdmin, requireGroupAdmin } = require('../config/passport');

const router = express.Router();
const prisma = new PrismaClient();

// ==================== POBIERANIE LISTY UŻYTKOWNIKÓW ====================

// Endpoint do pobierania listy wszystkich użytkowników (tylko dla superadmina)
router.get('/', requireSuperAdmin, [
  query('page').optional().isInt({ min: 1 }).withMessage('Numer strony musi być liczbą większą od 0'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit musi być liczbą od 1 do 100'),
  query('search').optional().isLength({ max: 100 }).withMessage('Wyszukiwanie max 100 znaków'),
  query('group').optional().isInt().withMessage('ID grupy musi być liczbą'),
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

    // Parametry paginacji i filtrowania
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search;
    const groupId = req.query.group ? parseInt(req.query.group) : null;
    const activeFilter = req.query.active !== undefined ? req.query.active === 'true' : null;

    // Budowanie warunków wyszukiwania
    const whereConditions = {};

    // Filtr aktywności
    if (activeFilter !== null) {
      whereConditions.isActive = activeFilter;
    }

    // Wyszukiwanie po imieniu, nazwisku lub emailu
    if (search) {
      whereConditions.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } }
      ];
    }

    // Filtr po grupie
    if (groupId) {
      whereConditions.userGroups = {
        some: {
          groupId: groupId
        }
      };
    }

    // Pobieranie użytkowników z paginacją
    const [users, totalCount] = await Promise.all([
      prisma.user.findMany({
        where: whereConditions,
        include: {
          userGroups: {
            include: {
              group: {
                select: {
                  id: true,
                  name: true,
                  color: true
                }
              }
            }
          },
          groupAdmins: {
            include: {
              group: {
                select: {
                  id: true,
                  name: true
                }
              }
            }
          }
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          accountType: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
          userGroups: true,
          groupAdmins: true
        },
        skip: skip,
        take: limit,
        orderBy: {
          createdAt: 'desc'
        }
      }),
      prisma.user.count({ where: whereConditions })
    ]);

    // Formatowanie danych odpowiedzi
    const formattedUsers = users.map(user => ({
      ...user,
      groups: user.userGroups.map(ug => ug.group),
      adminGroups: user.groupAdmins.map(ga => ga.group),
      userGroups: undefined, // Usuwamy surowe dane relacji
      groupAdmins: undefined
    }));

    res.json({
      users: formattedUsers,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalCount / limit),
        totalUsers: totalCount,
        usersPerPage: limit,
        hasNextPage: page < Math.ceil(totalCount / limit),
        hasPrevPage: page > 1
      }
    });

  } catch (error) {
    console.error('Błąd podczas pobierania użytkowników:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania użytkowników'
    });
  }
});

// ==================== POBIERANIE UŻYTKOWNIKÓW GRUPY ====================

// Endpoint dla administratorów grup - pobiera użytkowników z konkretnej grupy
router.get('/group/:groupId', requireAuth, [
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

    const groupId = parseInt(req.params.groupId);

    // Sprawdzamy uprawnienia - superadmin lub admin tej grupy
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;
    
    if (!isSuperAdmin) {
      const groupAdmin = await prisma.groupAdmin.findFirst({
        where: {
          userId: req.user.id,
          groupId: groupId
        }
      });

      if (!groupAdmin) {
        return res.status(403).json({
          error: 'Brak uprawnień do zarządzania tą grupą'
        });
      }
    }

    // Pobieramy użytkowników z grupy
    const groupUsers = await prisma.userGroup.findMany({
      where: {
        groupId: groupId
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            accountType: true,
            isActive: true,
            createdAt: true
          }
        }
      },
      orderBy: {
        addedAt: 'desc'
      }
    });

    // Pobieramy informacje o grupie
    const group = await prisma.group.findUnique({
      where: { id: groupId },
      select: {
        id: true,
        name: true,
        description: true,
        color: true
      }
    });

    if (!group) {
      return res.status(404).json({
        error: 'Grupa nie została znaleziona'
      });
    }

    res.json({
      group: group,
      users: groupUsers.map(gu => ({
        ...gu.user,
        addedAt: gu.addedAt,
        addedBy: gu.addedBy
      }))
    });

  } catch (error) {
    console.error('Błąd podczas pobierania użytkowników grupy:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania użytkowników grupy'
    });
  }
});

// ==================== POBIERANIE SZCZEGÓŁÓW UŻYTKOWNIKA ====================

router.get('/:id', requireAuth, [
  param('id').isInt().withMessage('ID użytkownika musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const userId = parseInt(req.params.id);
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Zwykły użytkownik może zobaczyć tylko swoje dane
    if (!isSuperAdmin && req.user.id !== userId) {
      // Sprawdzamy czy użytkownik jest administratorem jakiejś grupy,
      // w której znajduje się poszukiwany użytkownik
      const commonGroups = await prisma.groupAdmin.findMany({
        where: {
          userId: req.user.id,
          group: {
            userGroups: {
              some: {
                userId: userId
              }
            }
          }
        }
      });

      if (commonGroups.length === 0) {
        return res.status(403).json({
          error: 'Brak uprawnień do przeglądania tego użytkownika'
        });
      }
    }

    // Pobieramy dane użytkownika
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userGroups: {
          include: {
            group: {
              select: {
                id: true,
                name: true,
                description: true,
                color: true
              }
            }
          }
        },
        groupAdmins: {
          include: {
            group: {
              select: {
                id: true,
                name: true,
                description: true
              }
            }
          }
        }
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        accountType: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        userGroups: true,
        groupAdmins: true
      }
    });

    if (!user) {
      return res.status(404).json({
        error: 'Użytkownik nie został znaleziony'
      });
    }

    // Formatujemy odpowiedź
    const formattedUser = {
      ...user,
      groups: user.userGroups.map(ug => ({
        ...ug.group,
        addedAt: ug.addedAt,
        addedBy: ug.addedBy
      })),
      adminGroups: user.groupAdmins.map(ga => ga.group),
      userGroups: undefined,
      groupAdmins: undefined
    };

    res.json({ user: formattedUser });

  } catch (error) {
    console.error('Błąd podczas pobierania użytkownika:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania użytkownika'
    });
  }
});

// ==================== TWORZENIE NOWEGO UŻYTKOWNIKA ====================

// Walidatory dla tworzenia użytkownika
const createUserValidators = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Podaj prawidłowy adres email'),
  
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Imię musi mieć od 2 do 50 znaków'),
  
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Nazwisko musi mieć od 2 do 50 znaków'),
  
  body('password')
    .optional()
    .isLength({ min: 6 })
    .withMessage('Hasło musi mieć co najmniej 6 znaków'),
  
  body('groupIds')
    .optional()
    .isArray()
    .withMessage('Grupy muszą być tablicą ID'),
  
  body('groupIds.*')
    .optional()
    .isInt()
    .withMessage('ID grupy musi być liczbą')
];

router.post('/', requireSuperAdmin, createUserValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const { email, firstName, lastName, password, groupIds = [] } = req.body;

    // Sprawdzamy czy użytkownik już istnieje
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'Użytkownik o takim adresie email już istnieje'
      });
    }

    // Szyfrujemy hasło jeśli zostało podane
    let hashedPassword = null;
    if (password) {
      const saltRounds = 10;
      hashedPassword = await bcrypt.hash(password, saltRounds);
    }

    // Tworzymy użytkownika w transakcji (żeby przypisać grupy atomowo)
    const newUser = await prisma.$transaction(async (tx) => {
      // Tworzymy użytkownika
      const user = await tx.user.create({
        data: {
          email: email.toLowerCase(),
          firstName: firstName.trim(),
          lastName: lastName.trim(),
          password: hashedPassword,
          accountType: password ? 'local' : 'external',
          isActive: true
        }
      });

      // Przypisujemy do grup jeśli zostały podane
      if (groupIds.length > 0) {
        // Sprawdzamy czy wszystkie grupy istnieją
        const existingGroups = await tx.group.findMany({
          where: {
            id: { in: groupIds },
            isActive: true
          }
        });

        if (existingGroups.length !== groupIds.length) {
          throw new Error('Niektóre grupy nie istnieją lub są nieaktywne');
        }

        // Tworzymy powiązania użytkownik-grupa
        const userGroupsData = groupIds.map(groupId => ({
          userId: user.id,
          groupId: groupId,
          addedBy: req.user.id
        }));

        await tx.userGroup.createMany({
          data: userGroupsData
        });
      }

      return user;
    });

    // Pobieramy pełne dane użytkownika z grupami
    const userWithGroups = await prisma.user.findUnique({
      where: { id: newUser.id },
      include: {
        userGroups: {
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
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        accountType: true,
        isActive: true,
        createdAt: true,
        userGroups: true
      }
    });

    res.status(201).json({
      message: 'Użytkownik został utworzony pomyślnie',
      user: {
        ...userWithGroups,
        groups: userWithGroups.userGroups.map(ug => ug.group),
        userGroups: undefined
      }
    });

  } catch (error) {
    console.error('Błąd podczas tworzenia użytkownika:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas tworzenia użytkownika'
    });
  }
});

// ==================== AKTUALIZACJA UŻYTKOWNIKA ====================

const updateUserValidators = [
  param('id').isInt().withMessage('ID użytkownika musi być liczbą'),
  
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Imię musi mieć od 2 do 50 znaków'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Nazwisko musi mieć od 2 do 50 znaków'),
  
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive musi być true lub false')
];

router.put('/:id', requireAuth, updateUserValidators, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne dane',
        details: errors.array()
      });
    }

    const userId = parseInt(req.params.id);
    const { firstName, lastName, isActive } = req.body;
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Sprawdzamy uprawnienia
    if (!isSuperAdmin && req.user.id !== userId) {
      return res.status(403).json({
        error: 'Brak uprawnień do edycji tego użytkownika'
      });
    }

    // Sprawdzamy czy użytkownik istnieje
    const existingUser = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!existingUser) {
      return res.status(404).json({
        error: 'Użytkownik nie został znaleziony'
      });
    }

    // Przygotowujemy dane do aktualizacji
    const updateData = {};
    if (firstName !== undefined) updateData.firstName = firstName.trim();
    if (lastName !== undefined) updateData.lastName = lastName.trim();
    
    // Tylko superadmin może zmieniać status aktywności
    if (isActive !== undefined && isSuperAdmin) {
      updateData.isActive = isActive;
    }

    // Aktualizujemy użytkownika
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      include: {
        userGroups: {
          include: {
            group: {
              select: {
                id: true,
                name: true,
                color: true
              }
            }
          }
        },
        groupAdmins: {
          include: {
            group: {
              select: {
                id: true,
                name: true
              }
            }
          }
        }
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        accountType: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        userGroups: true,
        groupAdmins: true
      }
    });

    res.json({
      message: 'Użytkownik został zaktualizowany',
      user: {
        ...updatedUser,
        groups: updatedUser.userGroups.map(ug => ug.group),
        adminGroups: updatedUser.groupAdmins.map(ga => ga.group),
        userGroups: undefined,
        groupAdmins: undefined
      }
    });

  } catch (error) {
    console.error('Błąd podczas aktualizacji użytkownika:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas aktualizacji użytkownika'
    });
  }
});

// ==================== USUWANIE UŻYTKOWNIKA ====================

router.delete('/:id', requireSuperAdmin, [
  param('id').isInt().withMessage('ID użytkownika musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const userId = parseInt(req.params.id);

    // Sprawdzamy czy użytkownik nie próbuje usunąć samego siebie
    if (req.user.id === userId) {
      return res.status(400).json({
        error: 'Nie możesz usunąć własnego konta'
      });
    }

    // Sprawdzamy czy użytkownik istnieje
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      return res.status(404).json({
        error: 'Użytkownik nie został znaleziony'
      });
    }

    // Usuwamy użytkownika (Cascade automatycznie usuwa powiązania)
    await prisma.user.delete({
      where: { id: userId }
    });

    res.json({
      message: 'Użytkownik został usunięty',
      deletedUser: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });

  } catch (error) {
    console.error('Błąd podczas usuwania użytkownika:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas usuwania użytkownika'
    });
  }
});

module.exports = router;
