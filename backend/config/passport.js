// Konfiguracja Passport.js dla obsługi różnych strategii autentykacji
// Obsługuje logowanie lokalne (email/hasło) oraz OAuth (Google, Facebook, GitHub, Microsoft)

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// ==================== SERIALIZACJA UŻYTKOWNIKA ====================

// Określa jakie dane użytkownika zapisać w sesji (tylko ID dla wydajności)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Odczytuje pełne dane użytkownika z bazy na podstawie ID z sesji
passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: id },
      include: {
        userGroups: {
          include: {
            group: true // Dołączamy informacje o grupach użytkownika
          }
        },
        groupAdmins: {
          include: {
            group: true // Dołączamy informacje o grupach, którymi administruje
          }
        }
      }
    });
    
    if (!user) {
      return done(null, false);
    }
    
    // Dodajemy dodatkowe informacje o rolach użytkownika
    user.isSuperAdmin = user.email === process.env.SUPER_ADMIN_EMAIL;
    user.adminGroups = user.groupAdmins.map(ga => ga.group);
    user.memberGroups = user.userGroups.map(ug => ug.group);
    
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// ==================== STRATEGIA LOKALNA (EMAIL + HASŁO) ====================

passport.use(new LocalStrategy(
  {
    usernameField: 'email', // Używamy email zamiast username
    passwordField: 'password'
  },
  async (email, password, done) => {
    try {
      // Szukamy użytkownika po email
      const user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
        include: {
          userGroups: {
            include: {
              group: true
            }
          },
          groupAdmins: {
            include: {
              group: true
            }
          }
        }
      });

      // Sprawdzamy czy użytkownik istnieje
      if (!user) {
        return done(null, false, { message: 'Nieprawidłowy email lub hasło' });
      }

      // Sprawdzamy czy konto jest aktywne
      if (!user.isActive) {
        return done(null, false, { message: 'Konto zostało dezaktywowane' });
      }

      // Sprawdzamy czy to konto lokalne (ma hasło)
      if (!user.password) {
        return done(null, false, { 
          message: 'To konto używa logowania zewnętrznego (Google, Facebook, etc.)' 
        });
      }

      // Porównujemy hasło z zaszyfrowanym hasłem w bazie
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        return done(null, false, { message: 'Nieprawidłowy email lub hasło' });
      }

      // Logowanie udane - zwracamy użytkownika
      return done(null, user);
      
    } catch (error) {
      console.error('Błąd podczas logowania lokalnego:', error);
      return done(error);
    }
  }
));

// ==================== STRATEGIA GOOGLE OAUTH ====================

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/api/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Sprawdzamy czy użytkownik już istnieje (po Google ID lub email)
        let user = await prisma.user.findFirst({
          where: {
            OR: [
              { externalId: profile.id, accountType: 'google' },
              { email: profile.emails[0].value.toLowerCase() }
            ]
          },
          include: {
            userGroups: { include: { group: true } },
            groupAdmins: { include: { group: true } }
          }
        });

        if (user) {
          // Użytkownik istnieje - aktualizujemy dane Google jeśli potrzeba
          if (user.accountType !== 'google' || user.externalId !== profile.id) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: {
                externalId: profile.id,
                accountType: 'google',
                firstName: profile.name.givenName || user.firstName,
                lastName: profile.name.familyName || user.lastName
              },
              include: {
                userGroups: { include: { group: true } },
                groupAdmins: { include: { group: true } }
              }
            });
          }
        } else {
          // Nowy użytkownik - tworzymy konto
          user = await prisma.user.create({
            data: {
              email: profile.emails[0].value.toLowerCase(),
              firstName: profile.name.givenName || 'Użytkownik',
              lastName: profile.name.familyName || 'Google',
              accountType: 'google',
              externalId: profile.id,
              isActive: true
            },
            include: {
              userGroups: { include: { group: true } },
              groupAdmins: { include: { group: true } }
            }
          });
        }

        return done(null, user);
      } catch (error) {
        console.error('Błąd podczas logowania Google:', error);
        return done(error, null);
      }
    }
  ));
}

// ==================== STRATEGIA FACEBOOK OAUTH ====================

if (process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET) {
  passport.use(new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "/api/auth/facebook/callback",
      profileFields: ['id', 'emails', 'name'] // Określamy jakie dane chcemy otrzymać
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await prisma.user.findFirst({
          where: {
            OR: [
              { externalId: profile.id, accountType: 'facebook' },
              { email: profile.emails[0].value.toLowerCase() }
            ]
          },
          include: {
            userGroups: { include: { group: true } },
            groupAdmins: { include: { group: true } }
          }
        });

        if (user) {
          // Aktualizujemy istniejącego użytkownika
          if (user.accountType !== 'facebook' || user.externalId !== profile.id) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: {
                externalId: profile.id,
                accountType: 'facebook',
                firstName: profile.name.givenName || user.firstName,
                lastName: profile.name.familyName || user.lastName
              },
              include: {
                userGroups: { include: { group: true } },
                groupAdmins: { include: { group: true } }
              }
            });
          }
        } else {
          // Tworzymy nowego użytkownika
          user = await prisma.user.create({
            data: {
              email: profile.emails[0].value.toLowerCase(),
              firstName: profile.name.givenName || 'Użytkownik',
              lastName: profile.name.familyName || 'Facebook',
              accountType: 'facebook',
              externalId: profile.id,
              isActive: true
            },
            include: {
              userGroups: { include: { group: true } },
              groupAdmins: { include: { group: true } }
            }
          });
        }

        return done(null, user);
      } catch (error) {
        console.error('Błąd podczas logowania Facebook:', error);
        return done(error, null);
      }
    }
  ));
}

// ==================== STRATEGIA GITHUB OAUTH ====================

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/api/auth/github/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await prisma.user.findFirst({
          where: {
            OR: [
              { externalId: profile.id, accountType: 'github' },
              { email: profile.emails[0].value.toLowerCase() }
            ]
          },
          include: {
            userGroups: { include: { group: true } },
            groupAdmins: { include: { group: true } }
          }
        });

        if (user) {
          if (user.accountType !== 'github' || user.externalId !== profile.id) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: {
                externalId: profile.id,
                accountType: 'github',
                firstName: profile.displayName?.split(' ')[0] || user.firstName,
                lastName: profile.displayName?.split(' ').slice(1).join(' ') || user.lastName
              },
              include: {
                userGroups: { include: { group: true } },
                groupAdmins: { include: { group: true } }
              }
            });
          }
        } else {
          const nameParts = profile.displayName ? profile.displayName.split(' ') : ['Użytkownik', 'GitHub'];
          user = await prisma.user.create({
            data: {
              email: profile.emails[0].value.toLowerCase(),
              firstName: nameParts[0] || 'Użytkownik',
              lastName: nameParts.slice(1).join(' ') || 'GitHub',
              accountType: 'github',
              externalId: profile.id,
              isActive: true
            },
            include: {
              userGroups: { include: { group: true } },
              groupAdmins: { include: { group: true } }
            }
          });
        }

        return done(null, user);
      } catch (error) {
        console.error('Błąd podczas logowania GitHub:', error);
        return done(error, null);
      }
    }
  ));
}

// ==================== STRATEGIA MICROSOFT OAUTH ====================

if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  passport.use(new MicrosoftStrategy(
    {
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: "/api/auth/microsoft/callback",
      scope: ['user.read']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await prisma.user.findFirst({
          where: {
            OR: [
              { externalId: profile.id, accountType: 'microsoft' },
              { email: profile.emails[0].value.toLowerCase() }
            ]
          },
          include: {
            userGroups: { include: { group: true } },
            groupAdmins: { include: { group: true } }
          }
        });

        if (user) {
          if (user.accountType !== 'microsoft' || user.externalId !== profile.id) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: {
                externalId: profile.id,
                accountType: 'microsoft',
                firstName: profile.name.givenName || user.firstName,
                lastName: profile.name.familyName || user.lastName
              },
              include: {
                userGroups: { include: { group: true } },
                groupAdmins: { include: { group: true } }
              }
            });
          }
        } else {
          user = await prisma.user.create({
            data: {
              email: profile.emails[0].value.toLowerCase(),
              firstName: profile.name.givenName || 'Użytkownik',
              lastName: profile.name.familyName || 'Microsoft',
              accountType: 'microsoft',
              externalId: profile.id,
              isActive: true
            },
            include: {
              userGroups: { include: { group: true } },
              groupAdmins: { include: { group: true } }
            }
          });
        }

        return done(null, user);
      } catch (error) {
        console.error('Błąd podczas logowania Microsoft:', error);
        return done(error, null);
      }
    }
  ));
}

// ==================== FUNKCJE POMOCNICZE ====================

// Middleware do sprawdzania czy użytkownik jest zalogowany
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Wymagane logowanie' });
};

// Middleware do sprawdzania czy użytkownik jest super administratorem
const requireSuperAdmin = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Wymagane logowanie' });
  }
  
  // Super admin to użytkownik z emailem zdefiniowanym w zmiennych środowiskowych
  if (req.user.email === process.env.SUPER_ADMIN_EMAIL) {
    return next();
  }
  
  res.status(403).json({ error: 'Brak uprawnień administratora' });
};

// Middleware do sprawdzania czy użytkownik może zarządzać konkretną grupą
const requireGroupAdmin = (groupId) => {
  return async (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Wymagane logowanie' });
    }
    
    // Super admin może wszystko
    if (req.user.email === process.env.SUPER_ADMIN_EMAIL) {
      return next();
    }
    
    // Sprawdzamy czy użytkownik jest administratorem tej grupy
    const groupAdmin = await prisma.groupAdmin.findFirst({
      where: {
        userId: req.user.id,
        groupId: parseInt(groupId)
      }
    });
    
    if (groupAdmin) {
      req.groupAdmin = groupAdmin; // Przekazujemy uprawnienia dalej
      return next();
    }
    
    res.status(403).json({ error: 'Brak uprawnień do zarządzania tą grupą' });
  };
};

module.exports.requireAuth = requireAuth;
module.exports.requireSuperAdmin = requireSuperAdmin;
module.exports.requireGroupAdmin = requireGroupAdmin;
