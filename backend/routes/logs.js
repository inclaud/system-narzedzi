// Trasy do zarządzania logami i raportami
// Obsługuje przeglądanie aktywności użytkowników oraz generowanie raportów

const express = require('express');
const { query, param, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { requireAuth, requireSuperAdmin } = require('../config/passport');

const router = express.Router();
const prisma = new PrismaClient();

// ==================== POBIERANIE LOGÓW AKTYWNOŚCI ====================

// Endpoint do pobierania logów aktywności (różne uprawnienia dla różnych użytkowników)
router.get('/activity', requireAuth, [
  query('page').optional().isInt({ min: 1 }).withMessage('Numer strony musi być liczbą większą od 0'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit musi być liczbą od 1 do 100'),
  query('userId').optional().isInt().withMessage('ID użytkownika musi być liczbą'),
  query('action').optional().isLength({ max: 100 }).withMessage('Akcja max 100 znaków'),
  query('dateFrom').optional().isISO8601().withMessage('Data od musi być w formacie ISO8601'),
  query('dateTo').optional().isISO8601().withMessage('Data do musi być w formacie ISO8601'),
  query('groupId').optional().isInt().withMessage('ID grupy musi być liczbą')
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
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;

    // Budowanie warunków wyszukiwania
    let whereConditions = {};

    // Superadmin może zobaczyć wszystkie logi
    // Administrator grupy może zobaczyć logi swojej grupy
    // Zwykły użytkownik może zobaczyć tylko swoje logi
    if (!isSuperAdmin) {
      // Sprawdzamy czy użytkownik jest administratorem jakichś grup
      const adminGroups = await prisma.groupAdmin.findMany({
        where: {
          userId: req.user.id,
          canViewReports: true
        },
        select: { groupId: true }
      });

      if (adminGroups.length > 0) {
        // Administrator grup - może zobaczyć logi swoich grup lub swoje
        const groupIds = adminGroups.map(ag => ag.groupId);
        whereConditions.OR = [
          { userId: req.user.id }, // Swoje logi
          { targetGroupId: { in: groupIds } }, // Logi dotyczące jego grup
          {
            userId: {
              in: await prisma.userGroup.findMany({
                where: { groupId: { in: groupIds } },
                select: { userId: true }
              }).then(ug => ug.map(u => u.userId))
            }
          } // Logi użytkowników z jego grup
        ];
      } else {
        // Zwykły użytkownik - tylko swoje logi
        whereConditions.userId = req.user.id;
      }
    }

    // Dodatkowe filtry (tylko dla superadmina lub jeśli dotyczą własnych danych)
    if (req.query.userId && (isSuperAdmin || parseInt(req.query.userId) === req.user.id)) {
      whereConditions.userId = parseInt(req.query.userId);
    }

    if (req.query.action) {
      whereConditions.action = {
        contains: req.query.action,
        mode: 'insensitive'
      };
    }

    if (req.query.dateFrom || req.query.dateTo) {
      whereConditions.createdAt = {};
      if (req.query.dateFrom) {
        whereConditions.createdAt.gte = new Date(req.query.dateFrom);
      }
      if (req.query.dateTo) {
        whereConditions.createdAt.lte = new Date(req.query.dateTo);
      }
    }

    if (req.query.groupId && isSuperAdmin) {
      whereConditions.targetGroupId = parseInt(req.query.groupId);
    }

    // Pobieranie logów z paginacją
    const [logs, totalCount] = await Promise.all([
      prisma.activityLog.findMany({
        where: whereConditions,
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true
            }
          },
          targetGroup: {
            select: {
              id: true,
              name: true
            }
          },
          targetTool: {
            select: {
              id: true,
              name: true
            }
          }
        },
        skip: skip,
        take: limit,
        orderBy: {
          createdAt: 'desc'
        }
      }),
      prisma.activityLog.count({ where: whereConditions })
    ]);

    // Formatowanie logów
    const formattedLogs = logs.map(log => ({
      id: log.id,
      action: log.action,
      details: log.details,
      createdAt: log.createdAt,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      user: log.user,
      targetGroup: log.targetGroup,
      targetTool: log.targetTool,
      // Ukrywamy wrażliwe dane dla nie-superadminów
      ...(isSuperAdmin ? {} : {
        ipAddress: log.userId === req.user.id ? log.ipAddress : null,
        userAgent: log.userId === req.user.id ? log.userAgent : null
      })
    }));

    res.json({
      logs: formattedLogs,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalCount / limit),
        totalLogs: totalCount,
        logsPerPage: limit,
        hasNextPage: page < Math.ceil(totalCount / limit),
        hasPrevPage: page > 1
      }
    });

  } catch (error) {
    console.error('Błąd podczas pobierania logów:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas pobierania logów'
    });
  }
});

// ==================== RAPORT AKTYWNOŚCI UŻYTKOWNIKÓW ====================

// Endpoint generujący raport aktywności użytkowników
router.get('/user-activity-report', requireAuth, [
  query('groupId').optional().isInt().withMessage('ID grupy musi być liczbą'),
  query('days').optional().isInt({ min: 1, max: 365 }).withMessage('Liczba dni musi być od 1 do 365'),
  query('userId').optional().isInt().withMessage('ID użytkownika musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const days = parseInt(req.query.days) || 30;
    const dateFrom = new Date();
    dateFrom.setDate(dateFrom.getDate() - days);
    
    const isSuperAdmin = req.user.email === process.env.SUPER_ADMIN_EMAIL;
    const groupId = req.query.groupId ? parseInt(req.query.groupId) : null;
    const userId = req.query.userId ? parseInt(req.query.userId) : null;

    // Sprawdzamy uprawnienia
    if (!isSuperAdmin) {
      if (groupId) {
        const groupAdmin = await prisma.groupAdmin.findFirst({
          where: {
            userId: req.user.id,
            groupId: groupId,
            canViewReports: true
          }
        });

        if (!groupAdmin) {
          return res.status(403).json({
            error: 'Brak uprawnień do przeglądania raportów tej grupy'
          });
        }
      } else if (userId && userId !== req.user.id) {
        return res.status(403).json({
          error: 'Brak uprawnień do przeglądania raportów innych użytkowników'
        });
      }
    }

    // Budowanie warunków dla raportu
    let userFilter = {};
    if (userId) {
      userFilter.id = userId;
    } else if (groupId) {
      userFilter.userGroups = {
        some: { groupId: groupId }
      };
    } else if (!isSuperAdmin) {
      userFilter.id = req.user.id;
    }

    // Pobieranie danych dla raportu
    const [
      userStats,
      toolAccesses,
      topActions,
      dailyActivity
    ] = await Promise.all([
      // Statystyki użytkowników
      prisma.user.findMany({
        where: userFilter,
        include: {
          _count: {
            select: {
              activityLogs: {
                where: {
                  createdAt: { gte: dateFrom }
                }
              },
              toolAccesses: {
                where: {
                  accessedAt: { gte: dateFrom }
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
          _count: true
        }
      }),

      // Najpopularniejsze narzędzia
      prisma.toolAccess.groupBy({
        by: ['toolId'],
        where: {
          accessedAt: { gte: dateFrom },
          ...(userId ? { userId: userId } : {}),
          ...(groupId ? {
            user: {
              userGroups: {
                some: { groupId: groupId }
              }
            }
          } : {})
        },
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        },
        take: 10
      }),

      // Najczęstsze akcje
      prisma.activityLog.groupBy({
        by: ['action'],
        where: {
          createdAt: { gte: dateFrom },
          ...(userId ? { userId: userId } : {}),
          ...(groupId ? {
            OR: [
              { targetGroupId: groupId },
              {
                user: {
                  userGroups: {
                    some: { groupId: groupId }
                  }
                }
              }
            ]
          } : {})
        },
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        },
        take: 10
      }),

      // Aktywność dzienna
      prisma.$queryRaw`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as activity_count,
          COUNT(DISTINCT user_id) as unique_users
        FROM activity_logs 
        WHERE created_at >= ${dateFrom}
          ${userId ? prisma.$queryRaw`AND user_id = ${userId}` : prisma.$queryRaw``}
        GROUP BY DATE(created_at)
        ORDER BY date DESC
        LIMIT 30
      `
    ]);

    // Pobieramy nazwy narzędzi dla statystyk
    const toolIds = toolAccesses.map(ta => ta.toolId);
    const tools = await prisma.tool.findMany({
      where: { id: { in: toolIds } },
      select: { id: true, name: true }
    });

    const toolsMap = tools.reduce((acc, tool) => {
      acc[tool.id] = tool.name;
      return acc;
    }, {});

    // Formatowanie odpowiedzi
    const report = {
      period: {
        days: days,
        from: dateFrom,
        to: new Date()
      },
      summary: {
        totalUsers: userStats.length,
        totalActivities: userStats.reduce((sum, user) => sum + user._count.activityLogs, 0),
        totalToolAccesses: userStats.reduce((sum, user) => sum + user._count.toolAccesses, 0),
        averageActivitiesPerUser: userStats.length > 0 ? 
          (userStats.reduce((sum, user) => sum + user._count.activityLogs, 0) / userStats.length).toFixed(2) : 0
      },
      users: userStats.map(user => ({
        id: user.id,
        email: user.email,
        name: `${user.firstName} ${user.lastName}`,
        activities: user._count.activityLogs,
        toolAccesses: user._count.toolAccesses
      })),
      topTools: toolAccesses.map(ta => ({
        toolId: ta.toolId,
        toolName: toolsMap[ta.toolId] || 'Nieznane narzędzie',
        accessCount: ta._count.id
      })),
      topActions: topActions.map(ta => ({
        action: ta.action,
        count: ta._count.id
      })),
      dailyActivity: dailyActivity.map(da => ({
        date: da.date,
        activityCount: parseInt(da.activity_count),
        uniqueUsers: parseInt(da.unique_users)
      }))
    };

    res.json({ report: report });

  } catch (error) {
    console.error('Błąd podczas generowania raportu:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas generowania raportu'
    });
  }
});

// ==================== RAPORT WYKORZYSTANIA NARZĘDZI ====================

router.get('/tools-usage-report', requireSuperAdmin, [
  query('days').optional().isInt({ min: 1, max: 365 }).withMessage('Liczba dni musi być od 1 do 365'),
  query('groupId').optional().isInt().withMessage('ID grupy musi być liczbą')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const days = parseInt(req.query.days) || 30;
    const groupId = req.query.groupId ? parseInt(req.query.groupId) : null;
    const dateFrom = new Date();
    dateFrom.setDate(dateFrom.getDate() - days);

    // Statystyki wykorzystania narzędzi
    const toolUsageStats = await prisma.tool.findMany({
      where: {
        isActive: true,
        ...(groupId ? {
          groupTools: {
            some: { groupId: groupId }
          }
        } : {})
      },
      include: {
        _count: {
          select: {
            toolAccesses: {
              where: {
                accessedAt: { gte: dateFrom },
                ...(groupId ? {
                  user: {
                    userGroups: {
                      some: { groupId: groupId }
                    }
                  }
                } : {})
              }
            },
            groupTools: true
          }
        },
        groupTools: {
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
      orderBy: {
        name: 'asc'
      }
    });

    // Statystyki unikalnych użytkowników na narzędzie
    const uniqueUsersPerTool = await Promise.all(
      toolUsageStats.map(async (tool) => {
        const uniqueUsers = await prisma.toolAccess.findMany({
          where: {
            toolId: tool.id,
            accessedAt: { gte: dateFrom },
            ...(groupId ? {
              user: {
                userGroups: {
                  some: { groupId: groupId }
                }
              }
            } : {})
          },
          select: { userId: true },
          distinct: ['userId']
        });

        return {
          toolId: tool.id,
          uniqueUsers: uniqueUsers.length
        };
      })
    );

    const uniqueUsersMap = uniqueUsersPerTool.reduce((acc, item) => {
      acc[item.toolId] = item.uniqueUsers;
      return acc;
    }, {});

    // Formatowanie raportu
    const report = {
      period: {
        days: days,
        from: dateFrom,
        to: new Date()
      },
      tools: toolUsageStats.map(tool => ({
        id: tool.id,
        name: tool.name,
        description: tool.description,
        category: tool.category,
        isExternal: tool.isExternal,
        totalAccesses: tool._count.toolAccesses,
        uniqueUsers: uniqueUsersMap[tool.id] || 0,
        groupCount: tool._count.groupTools,
        groups: tool.groupTools.map(gt => gt.group),
        avgAccessesPerUser: uniqueUsersMap[tool.id] > 0 ? 
          (tool._count.toolAccesses / uniqueUsersMap[tool.id]).toFixed(2) : 0
      })).sort((a, b) => b.totalAccesses - a.totalAccesses),
      summary: {
        totalTools: toolUsageStats.length,
        totalAccesses: toolUsageStats.reduce((sum, tool) => sum + tool._count.toolAccesses, 0),
        mostPopularTool: toolUsageStats.reduce((max, tool) => 
          tool._count.toolAccesses > (max?._count?.toolAccesses || 0) ? tool : max, null
        ),
        leastUsedTools: toolUsageStats.filter(tool => tool._count.toolAccesses === 0).length
      }
    };

    res.json({ report: report });

  } catch (error) {
    console.error('Błąd podczas generowania raportu narzędzi:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas generowania raportu narzędzi'
    });
  }
});

// ==================== RAPORT GRUP ====================

router.get('/groups-report', requireSuperAdmin, [
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

    // Statystyki grup
    const groupStats = await prisma.group.findMany({
      where: {
        ...(includeInactive ? {} : { isActive: true })
      },
      include: {
        _count: {
          select: {
            userGroups: true,
            groupAdmins: true,
            groupTools: true
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

    // Ostatnia aktywność w grupach
    const groupActivity = await Promise.all(
      groupStats.map(async (group) => {
        const lastActivity = await prisma.activityLog.findFirst({
          where: {
            OR: [
              { targetGroupId: group.id },
              {
                user: {
                  userGroups: {
                    some: { groupId: group.id }
                  }
                }
              }
            ]
          },
          orderBy: {
            createdAt: 'desc'
          }
        });

        return {
          groupId: group.id,
          lastActivity: lastActivity?.createdAt || null
        };
      })
    );

    const activityMap = groupActivity.reduce((acc, item) => {
      acc[item.groupId] = item.lastActivity;
      return acc;
    }, {});

    // Formatowanie raportu
    const report = {
      groups: groupStats.map(group => ({
        id: group.id,
        name: group.name,
        description: group.description,
        color: group.color,
        isActive: group.isActive,
        createdAt: group.createdAt,
        userCount: group._count.userGroups,
        adminCount: group._count.groupAdmins,
        toolCount: group._count.groupTools,
        lastActivity: activityMap[group.id],
        admins: group.groupAdmins.map(ga => ({
          id: ga.user.id,
          name: `${ga.user.firstName} ${ga.user.lastName}`,
          email: ga.user.email,
          permissions: {
            canAddUsers: ga.canAddUsers,
            canEditUsers: ga.canEditUsers,
            canRemoveUsers: ga.canRemoveUsers,
            canManageUsers: ga.canManageUsers,
            canViewReports: ga.canViewReports
          }
        }))
      })),
      summary: {
        totalGroups: groupStats.length,
        activeGroups: groupStats.filter(g => g.isActive).length,
        inactiveGroups: groupStats.filter(g => !g.isActive).length,
        totalUsers: groupStats.reduce((sum, group) => sum + group._count.userGroups, 0),
        totalAdmins: groupStats.reduce((sum, group) => sum + group._count.groupAdmins, 0),
        averageUsersPerGroup: groupStats.length > 0 ? 
          (groupStats.reduce((sum, group) => sum + group._count.userGroups, 0) / groupStats.length).toFixed(2) : 0,
        groupsWithoutUsers: groupStats.filter(g => g._count.userGroups === 0).length,
        groupsWithoutAdmins: groupStats.filter(g => g._count.groupAdmins === 0).length
      }
    };

    res.json({ report: report });

  } catch (error) {
    console.error('Błąd podczas generowania raportu grup:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas generowania raportu grup'
    });
  }
});

// ==================== EKSPORT LOGÓW ====================

router.get('/export', requireSuperAdmin, [
  query('format').isIn(['json', 'csv']).withMessage('Format musi być json lub csv'),
  query('dateFrom').optional().isISO8601().withMessage('Data od musi być w formacie ISO8601'),
  query('dateTo').optional().isISO8601().withMessage('Data do musi być w formacie ISO8601'),
  query('limit').optional().isInt({ min: 1, max: 10000 }).withMessage('Limit musi być od 1 do 10000')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Błędne parametry',
        details: errors.array()
      });
    }

    const format = req.query.format;
    const limit = parseInt(req.query.limit) || 1000;
    
    let whereConditions = {};
    if (req.query.dateFrom || req.query.dateTo) {
      whereConditions.createdAt = {};
      if (req.query.dateFrom) {
        whereConditions.createdAt.gte = new Date(req.query.dateFrom);
      }
      if (req.query.dateTo) {
        whereConditions.createdAt.lte = new Date(req.query.dateTo);
      }
    }

    // Pobieranie logów
    const logs = await prisma.activityLog.findMany({
      where: whereConditions,
      include: {
        user: {
          select: {
            email: true,
            firstName: true,
            lastName: true
          }
        }
      },
      take: limit,
      orderBy: {
        createdAt: 'desc'
      }
    });

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=logs_${new Date().toISOString().split('T')[0]}.json`);
      res.json(logs);
    } else if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=logs_${new Date().toISOString().split('T')[0]}.csv`);
      
      // Nagłówki CSV
      const csvHeaders = 'ID,Data,Akcja,Użytkownik,Email,IP,Szczegóły\n';
      
      // Konwersja do CSV
      const csvData = logs.map(log => {
        const userName = log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System';
        const userEmail = log.user?.email || '';
        const details = JSON.stringify(log.details || {}).replace(/"/g, '""');
        
        return `${log.id},"${log.createdAt.toISOString()}","${log.action}","${userName}","${userEmail}","${log.ipAddress || ''}","${details}"`;
      }).join('\n');
      
      res.send(csvHeaders + csvData);
    }

  } catch (error) {
    console.error('Błąd podczas eksportu logów:', error);
    res.status(500).json({
      error: 'Błąd serwera podczas eksportu logów'
    });
  }
});

module.exports = router;
