// Plik konfiguracyjny Prisma ORM - definiuje strukturę bazy danych
// oraz sposób połączenia z PostgreSQL

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Model użytkownika - główna tabela z danymi użytkowników
model User {
  id        Int      @id @default(autoincrement()) // Unikalny identyfikator użytkownika
  email     String   @unique // Email - musi być unikalny w systemie
  password  String?  // Hasło (nullable - dla użytkowników OAuth może być puste)
  firstName String   // Imię użytkownika
  lastName  String   // Nazwisko użytkownika
  isActive  Boolean  @default(true) // Czy konto jest aktywne (można dezaktywować zamiast usuwać)
  createdAt DateTime @default(now()) // Data utworzenia konta
  updatedAt DateTime @updatedAt // Data ostatniej aktualizacji danych
  
  // Typ konta użytkownika (lokalny lub OAuth)
  accountType String @default("local") // "local", "google", "microsoft", "github", "facebook"
  
  // Zewnętrzne ID dla kont OAuth (np. Google ID, Facebook ID)
  externalId String?
  
  // Relacje z innymi tabelami
  userGroups    UserGroup[]    // Grupy, do których należy użytkownik
  groupAdmins   GroupAdmin[]   // Grupy, którymi administruje
  activityLogs  ActivityLog[]  // Wszystkie akcje użytkownika w systemie
  toolAccesses  ToolAccess[]   // Historia dostępu do narzędzi
  
  @@map("users") // Nazwa tabeli w bazie danych
}

// Model grupy użytkowników - pozwala grupować użytkowników w logiczne całości
model Group {
  id          Int      @id @default(autoincrement())
  name        String   @unique // Nazwa grupy (musi być unikalna)
  description String?  // Opcjonalny opis grupy
  isActive    Boolean  @default(true) // Czy grupa jest aktywna
  color       String?  // Kolor grupy do wyświetlenia w interfejsie (hex)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  
  // Relacje
  userGroups     UserGroup[]     // Użytkownicy w tej grupie
  groupAdmins    GroupAdmin[]    // Administratorzy tej grupy
  groupTools     GroupTool[]     // Narzędzia dostępne dla tej grupy
  activityLogs   ActivityLog[]   // Logi aktywności związane z grupą
  
  @@map("groups")
}

// Tabela łącząca użytkowników z grupami (relacja many-to-many)
// Jeden użytkownik może należeć do wielu grup
model UserGroup {
  id        Int      @id @default(autoincrement())
  userId    Int      // ID użytkownika
  groupId   Int      // ID grupy
  addedAt   DateTime @default(now()) // Kiedy użytkownik został dodany do grupy
  addedBy   Int?     // Kto dodał użytkownika (ID administratora)
  
  // Relacje
  user  User  @relation(fields: [userId], references: [id], onDelete: Cascade)
  group Group @relation(fields: [groupId], references: [id], onDelete: Cascade)
  
  // Jeden użytkownik może być tylko raz w jednej grupie
  @@unique([userId, groupId])
  @@map("user_groups")
}

// Administratorzy grup - użytkownicy z uprawnieniami do zarządzania konkretną grupą
model GroupAdmin {
  id      Int @id @default(autoincrement())
  userId  Int // ID użytkownika-administratora
  groupId Int // ID grupy, którą administruje
  
  // Szczegółowe uprawnienia administratora grupy
  canAddUsers    Boolean @default(true)  // Może dodawać użytkowników
  canEditUsers   Boolean @default(true)  // Może edytować dane użytkowników
  canRemoveUsers Boolean @default(true)  // Może usuwać użytkowników z grupy
  canManageUsers Boolean @default(true)  // Może przypisywać/usuwać z grupy
  canViewReports Boolean @default(false) // Może przeglądać raporty grupy
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  // Relacje
  user  User  @relation(fields: [userId], references: [id], onDelete: Cascade)
  group Group @relation(fields: [groupId], references: [id], onDelete: Cascade)
  
  // Jeden użytkownik może być administratorem jednej grupy tylko raz
  @@unique([userId, groupId])
  @@map("group_admins")
}

// Model narzędzia - reprezentuje pojedyncze narzędzie w katalogu
model Tool {
  id          Int      @id @default(autoincrement())
  name        String   // Nazwa narzędzia
  description String?  // Opis narzędzia
  url         String   // URL do narzędzia (może być wewnętrzny lub zewnętrzny)
  icon        String?  // Ścieżka do ikony narzędzia
  category    String?  // Kategoria narzędzia (opcjonalna)
  isActive    Boolean  @default(true) // Czy narzędzie jest aktywne
  isExternal  Boolean  @default(false) // Czy link prowadzi na zewnątrz
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  
  // Relacje
  groupTools   GroupTool[]   // Grupy mające dostęp do tego narzędzia
  toolAccesses ToolAccess[]  // Historia dostępu do narzędzia
  activityLogs ActivityLog[] // Logi związane z narzędziem
  
  @@map("tools")
}

// Uprawnienia grup do narzędzi - definiuje jakie grupy mają dostęp do jakich narzędzi
model GroupTool {
  id        Int      @id @default(autoincrement())
  groupId   Int      // ID grupy
  toolId    Int      // ID narzędzia
  
  // Poziom dostępu do narzędzia
  accessLevel String @default("read") // "read" (tylko czytanie) lub "write" (edycja)
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  // Relacje
  group Group @relation(fields: [groupId], references: [id], onDelete: Cascade)
  tool  Tool  @relation(fields: [toolId], references: [id], onDelete: Cascade)
  
  // Jedna grupa może mieć tylko jeden poziom dostępu do jednego narzędzia
  @@unique([groupId, toolId])
  @@map("group_tools")
}

// Historia dostępu do narzędzi - loguje każde użycie narzędzia przez użytkownika
model ToolAccess {
  id         Int      @id @default(autoincrement())
  userId     Int      // Kto używał narzędzia
  toolId     Int      // Jakiego narzędzia użył
  accessedAt DateTime @default(now()) // Kiedy użył
  ipAddress  String?  // Z jakiego IP
  userAgent  String?  // Jakiej przeglądarki użył
  
  // Relacje
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
  tool Tool @relation(fields: [toolId], references: [id], onDelete: Cascade)
  
  @@map("tool_accesses")
}

// Uniwersalny log wszystkich aktywności w systemie
model ActivityLog {
  id        Int      @id @default(autoincrement())
  userId    Int?     // Kto wykonał akcję (może być null dla akcji systemowych)
  action    String   // Typ akcji (np. "USER_CREATED", "GROUP_MODIFIED", "TOOL_ACCESSED")
  
  // Szczegóły akcji w formacie JSON
  details   Json?    // Dodatkowe informacje o akcji
  
  // Opcjonalne powiązania z konkretnymi rekordami
  targetUserId  Int?  // ID użytkownika, którego dotyczy akcja
  targetGroupId Int?  // ID grupy, której dotyczy akcja  
  targetToolId  Int?  // ID narzędzia, którego dotyczy akcja
  
  // Informacje techniczne
  ipAddress String?  // IP użytkownika
  userAgent String?  // Przeglądarka użytkownika
  
  createdAt DateTime @default(now()) // Kiedy nastąpiła akcja
  
  // Relacje
  user        User?  @relation(fields: [userId], references: [id], onDelete: SetNull)
  targetGroup Group? @relation(fields: [targetGroupId], references: [id], onDelete: SetNull)
  targetTool  Tool?  @relation(fields: [targetToolId], references: [id], onDelete: SetNull)
  
  @@map("activity_logs")
}

// Tabela sesji użytkowników (dla express-session)
model Session {
  id        String   @id
  sid       String   @unique
  data      String
  expiresAt DateTime
  
  @@map("sessions")
}
