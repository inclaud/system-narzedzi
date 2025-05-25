// Główny plik serwera Express.js dla systemu zarządzania narzędziami
// Konfiguruje wszystkie middleware'y, routes i połączenie z bazą danych

// Importowanie wymaganych modułów
const express = require('express');           // Framework webowy dla Node.js
const cors = require('cors');                 // Obsługa Cross-Origin Resource Sharing
const helmet = require('helmet');             // Zabezpieczenia HTTP headers
const session = require('express-session');   // Zarządzanie sesjami użytkowników
const passport = require('passport');         // Middleware do autentykacji
const rateLimit = require('express-rate-limit'); // Ograniczanie liczby requestów
const { PrismaClient } = require('@prisma/client'); // ORM do bazy danych
const PgSession = require('connect-pg-simple')(session); // Store sesji w PostgreSQL

// Ładowanie zmiennych środowiskowych z pliku .env
require('dotenv').config();

// Importowanie naszych modułów
const authRoutes = require('./routes/auth');       // Trasy autentykacji
const userRoutes = require('./routes/users');      // Trasy zarządzania użytkownikami
const groupRoutes = require('./routes/groups');    // Trasy zarządzania grupami
const toolRoutes = require('./routes/tools');      // Trasy zarządzania narzędziami
const logRoutes = require('./routes/logs');        // Trasy do logów i raportów
const passportConfig = require('./config/passport'); // Konfiguracja Passport.js

// Inicjalizacja aplikacji Express i klienta Prisma
const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;

// ==================== MIDDLEWARE KONFIGURACJA ====================

// Helmet - dodaje podstawowe zabezpieczenia HTTP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Pozwala na inline CSS
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS - pozwala na połączenia z frontendu
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000', // URL frontendu
  credentials: true, // Pozwala na wysyłanie cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting - ogranicza liczbę requestów na IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 100, // Maksymalnie 100 requestów na IP w oknie czasowym
  message: {
    error: 'Zbyt wiele requestów z tego IP, spróbuj ponownie za 15 minut'
  }
});
app.use(limiter);

// Parsowanie JSON i URL-encoded danych
app.use(express.json({ limit: '10mb' })); // Maksymalny rozmiar JSON: 10MB
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Konfiguracja sesji - przechowywane w PostgreSQL
app.use(session({
  store: new PgSession({
    conString: process.env.DATABASE_URL, // Połączenie z bazą danych
    tableName: 'sessions', // Nazwa tabeli dla sesji
    createTableIfMissing: true, // Automatyczne tworzenie tabeli
  }),
  secret: process.env.SECRET_KEY || 'fallback-secret-key',
  resave: false, // Nie zapisuj sesji jeśli nie była modyfikowana
  saveUninitialized: false, // Nie zapisuj pustych sesji
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS tylko w produkcji
    httpOnly: true, // Cookie niedostępne z JavaScript
    maxAge: 24 * 60 * 60 * 1000 // 24 godziny
  }
}));

// Inicjalizacja Passport.js dla autentykacji
app.use(passport.initialize());
app.use(passport.session());

// ==================== MIDDLEWARE DO LOGOWANIA AKTYWNOŚCI ====================

// Middleware który loguje wszystkie ważne akcje użytkowników
const activityLogger = async (req, res, next) => {
  // Zapisujemy oryginalną metodę res.json żeby móc przechwycić odpowiedź
  const originalJson = res.json;
  
  res.json = function(data) {
    // Logujemy akcję tylko jeśli operacja zakończyła się sukcesem
    if (res.statusCode >= 200 && res.statusCode < 300) {
      // Asynchroniczne logowanie żeby nie blokować odpowiedzi
      setImmediate(async () => {
        try {
          // Określamy typ akcji na podstawie metody i ścieżki
          let action = `${req.method}_${req.path.replace(/\//g, '_').toUpperCase()}`;
          
          // Szczegółowe informacje o akcji
          const logData = {
            userId: req.user?.id || null,
            action: action,
            details: {
              method: req.method,
              path: req.path,
              query: req.query,
              // Nie logujemy haseł ani innych wrażliwych danych
              body: req.method === 'POST' || req.method === 'PUT' ? 
                    { ...req.body, password: undefined } : undefined,
              responseStatus: res.statusCode
            },
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
          };

          // Zapisujemy do bazy danych
          await prisma.activityLog.create({
            data: logData
          });
        } catch (error) {
          console.error('Błąd podczas logowania aktywności:', error);
        }
      });
    }
    
    // Wywołujemy oryginalną metodę json
    return originalJson.call(this, data);
  };
  
  next();
};

// Stosujemy middleware do logowania dla wszystkich tras
app.use(activityLogger);

// ==================== TRASY (ROUTES) ====================

// Podstawowa trasa testowa
app.get('/', (req, res) => {
  res.json({ 
    message: 'System Zarządzania Narzędziami - API',
    version: '1.0.0',
    status: 'running'
  });
});

// Podłączanie tras z odpowiednimi prefiksami
app.use('/api/auth', authRoutes);      // Trasy autentykacji: /api/auth/*
app.use('/api/users', userRoutes);     // Zarządzanie użytkownikami: /api/users/*
app.use('/api/groups', groupRoutes);   // Zarządzanie grupami: /api/groups/*
app.use('/api/tools', toolRoutes);     // Zarządzanie narzędziami: /api/tools/*
app.use('/api/logs', logRoutes);       // Logi i raporty: /api/logs/*

// ==================== MIDDLEWARE OBSŁUGI BŁĘDÓW ====================

// Middleware do obsługi 404 - gdy trasa nie została znaleziona
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint nie został znaleziony',
    path: req.originalUrl,
    method: req.method
  });
});

// Globalny middleware obsługi błędów - musi być na końcu
app.use((error, req, res, next) => {
  console.error('Błąd serwera:', error);
  
  // W środowisku produkcyjnym nie pokazujemy szczegółów błędu
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(error.status || 500).json({
    error: 'Wystąpił błąd serwera',
    message: isDevelopment ? error.message : 'Spróbuj ponownie później',
    ...(isDevelopment && { stack: error.stack })
  });
});

// ==================== URUCHOMIENIE SERWERA ====================

// Funkcja do graceful shutdown - prawidłowe zamknięcie połączeń
const gracefulShutdown = async (signal) => {
  console.log(`\nOtrzymano sygnał ${signal}. Zamykanie serwera...`);
  
  try {
    // Zamknięcie połączenia z bazą danych
    await prisma.$disconnect();
    console.log('Połączenie z bazą danych zostało zamknięte');
    
    // Zakończenie procesu
    process.exit(0);
  } catch (error) {
    console.error('Błąd podczas zamykania:', error);
    process.exit(1);
  }
};

// Nasłuchiwanie sygnałów systemowych
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Startowanie serwera
app.listen(PORT, async () => {
  try {
    // Testowanie połączenia z bazą danych
    await prisma.$connect();
    console.log('✅ Połączenie z bazą danych zostało nawiązane');
    
    console.log(`🚀 Serwer uruchomiony na porcie ${PORT}`);
    console.log(`📊 Panel admina dostępny na: http://localhost:${PORT}`);
    console.log(`🔐 Dokumentacja API: http://localhost:${PORT}/api`);
    
  } catch (error) {
    console.error('❌ Błąd podczas uruchamiania serwera:', error);
    process.exit(1);
  }
});

// Eksportujemy app i prisma dla testów
module.exports = { app, prisma };
