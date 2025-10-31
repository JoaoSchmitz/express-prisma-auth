# Express Prisma Auth

Um módulo de autenticação reutilizável e seguro para aplicações Node.js que usam Express e Prisma. Fornece rotas, serviços e middlewares prontos para uso, baseados em tokens JWT e com as melhores práticas de segurança.

Este pacote foi criado para ser agnóstico à lógica de negócios, usando injeção de dependência para se integrar a qualquer aplicação Express/Prisma.

## 🚀 Funcionalidades

- **Autenticação baseada em JWT:** Usa `accessToken` (curta duração) e `refreshToken` (longa duração).

- **Segurança de Refresh Token:** Implementa o padrão **Selector/Validator** com tokens armazenados em cookies `HttpOnly` e `secure`.

- **Registro de Usuário:** Criação de usuário com hash de senha seguro (`bcrypt`).

- **Verificação de Email:** Fluxo completo com envio de token para verificação de email.

- **Recuperação de Senha:** Fluxo completo para "Esqueci minha senha".

- **Atualização Segura de Email:** Exige senha do usuário e envia verificação para o _novo_ email.

- **Atualização Segura de Senha:** Exige a senha antiga do usuário logado.

- **Segurança de Token:** Todos os tokens de uso único (email, reset) são **hashados (SHA-256)** no banco de dados.

- **Invalidação de Sessão:** Todas as sessões (refresh tokens) são automaticamente invalidadas após mudança de senha ou email.

- **Autorização (RBAC):** Inclui middleware `ensureRole` para verificação de cargos (ex: `ADMIN`).

- **Injeção de Dependência:** Desacoplado da lógica de negócios. O app consumidor injeta o `PrismaClient`, `emailService` e `URLs` de frontend.

- **Hooks de Evento:** Permite injetar lógica customizada (ex: criar um `RelatorioUsuario`) dentro da transação de registro.

## ⚙️ Instalação

Este pacote é publicado no [GitHub Packages](https://npm.pkg.github.com/).

1. **Instale o pacote:**

   ```bash
   npm install @joaoschmitz/express-prisma-auth
   ```

   _(**Nota:** O pacote já inclui `cookie-parser` como dependência, você não precisa instalá-lo no seu app principal.)_

2. **Configure o `.npmrc`:**
   Para que o NPM saiba onde encontrar o pacote, crie um arquivo `.npmrc` na raiz do seu projeto (ex: `sabor-na-nuvem-api`) com a seguinte linha:

   ```
   @joaoschmitz:registry=[https://npm.pkg.github.com](https://npm.pkg.github.com)
   ```

## 📚 Configuração e Uso (Guia Rápido)

Para usar este pacote, você precisa fazer duas coisas:

1. **Cumprir o "Contrato" do `schema.prisma`**.

2. **Injetar suas dependências** no `createAuthModule`.

### 1. O Contrato do `schema.prisma`

Seu `schema.prisma` **DEVE** conter os modelos e enums abaixo para que este pacote funcione. Você deve mesclar este código com seu schema existente e rodar `npx prisma migrate dev`.

```prisma
// --- INÍCIO DO CONTRATO DE AUTENTICAÇÃO ---
// Seu schema.prisma DEVE conter o seguinte:

model Usuario {
  id String @id @default(uuid()) @map("idUsuario")
  nome String @map("nomeUsuario")
  email String @unique
  senha String

  // O pacote espera que este campo exista.
  // O valor (@default) será injetado pelo app consumidor.
  cargo RoleUsuario

  // CAMPO OBRIGATÓRIO para verificação de email
  emailVerificado Boolean @default(false)

  // Relações que o pacote de auth precisa gerenciar
  authTokens AuthToken[]
  authRefreshTokens AuthRefreshToken[]

  // ... (Adicione aqui suas outras relações, ex: Pedido[], Carrinho?, etc.)

@@map("usuario")
}

// OBRIGATÓRIO: Para verificação de email e reset de senha
model AuthToken {
  id String @id @default(uuid())
  token String @unique // Este será o HASH (SHA-256) do token
  tipo AuthTokenType
  expiresAt DateTime
  usado Boolean @default(false)
  payload Json? // Para armazenar dados extras (ex: novo email em EMAIL_UPDATE)

  usuarioId String
  usuario Usuario @relation(fields: [usuarioId], references: [id], onDelete:  Cascade)

  createdAt DateTime @default(now())
  @@map("authToken")
}

// OBRIGATÓRIO: Para Refresh Tokens (JWT)
model AuthRefreshToken {
  id String @id @default(uuid())
  selector String @unique // O "seletor" público para busca rápida
  validatorHash String // O "verificador" secreto hashado (SHA-256)
  expiresAt DateTime
  revogado Boolean @default(false) // Para o logout

  usuarioId String
  usuario Usuario @relation(fields: [usuarioId], references: [id], onDelete:  Cascade)

  createdAt DateTime @default(now())
@@map("authRefreshToken")
}

// --- ENUMS OBRIGATÓRIOS ---

// Você deve definir este enum com seus próprios cargos
enum RoleUsuario {
  CLIENTE
  FUNCIONARIO
  ADMIN
  // ... (ou LEITOR, AUTOR, etc.)
}

// Você deve definir este enum exatamente assim
enum AuthTokenType {
  EMAIL_VERIFICATION
  PASSWORD_RESET
  EMAIL_UPDATE
}

// --- FIM DO CONTRATO DE AUTENTICAÇÃO ---
```

### 2. Variáveis de Ambiente

Seu arquivo `.env` deve conter, no mínimo:

```.env

# ... (sua DATABASE_URL)

JWT_SECRET="seu-segredo-super-secreto-para-access-tokens"
```

### 3. Injetando Dependências (Exemplo de `app.js`)

Este é o "cérebro" da integração. No `app.js` do seu projeto principal, você importa e configura o módulo de autenticação.

```javascript
// Em src/app.js (do seu projeto)

import express from "express";
import { RoleUsuario } from "@prisma/client";
import prisma from "./config/prisma.js"; // 1. Seu PrismaClient local
import { createAuthModule } from "@joaoschmitz/express-prisma-auth";

// 2. Seu serviço de Email (você deve implementá-lo)
const emailService = {
  sendVerificationEmail: async (to, token) => {
    const url = `http://localhost:3000/api/auth/verify-email?token=${token}`;
    console.log(`[MOCK EMAIL] Para: ${to} | Verifique em: ${url}`);
    // (Implemente com SendGrid, Mailgun, etc.)
  },
  sendPasswordResetEmail: async (to, token) => {
    const url = `http://localhost:3001/reset-password?token=${token}`;
    console.log(`[MOCK EMAIL] Para: ${to} | Redefina em: ${url}`);
  },
  sendUpdateEmailConfirmation: async (to, token) => {
    const url = `http://localhost:3000/api/auth/verify-email-update?token=${token}`;
    console.log(`[MOCK EMAIL] Para: ${to} | Confirme o novo email em: ${url}`);
  },
};

// 3. Suas URLs de Frontend (para redirecionamentos)
const authRedirectUrls = {
  emailVerifySuccess: "http://localhost:3001/login?message=email-verificado",
  emailVerifyError: "http://localhost:3001/login?error=verificacao-falhou",
  passwordResetSuccess: "http://localhost:3001/login?message=senha-redefinida",
  passwordResetError:
    "http://localhost:3001/reset-password?error=token-invalido",
  emailUpdateSuccess: "http://localhost:3001/perfil?message=email-atualizado",
  emailUpdateError:
    "http://localhost:3001/perfil?error=email-atualizacao-falhou",
};

// 4. Seu Hook de Pós-Registro (Opcional)
const hookCriarRelatorio = async (tx, novoUsuario) => {
  await tx.relatorioUsuario.create({
    data: {
      usuarioId: novoUsuario.id,
    },
  });
};

// --- Configuração do App ---
const app = express();
app.use(express.json());

// --- INICIALIZAÇÃO DO PACOTE DE AUTENTICAÇÃO ---
const { authRoutes, authMiddleware } = createAuthModule({
  prismaClient: prisma,
  jwtSecret: process.env.JWT_SECRET,
  defaultUserRole: RoleUsuario.CLIENTE, // O cargo padrão para este app
  emailService: emailService,
  urls: authRedirectUrls,
  onUserRegistered: hookCriarRelatorio, // Opcional
});

// --- Uso das Rotas ---

// Monta todas as rotas de autenticação (ex: /login, /register)
app.use("/api/auth", authRoutes);

// Protege as rotas do seu aplicativo
app.use(
  "/api/pedidos",
  authMiddleware.ensureAuthenticated, // 1. Está logado?
  pedidoRoutes
);
app.use(
  "/api/admin/painel",
  authMiddleware.ensureAuthenticated, // 1. Está logado?
  authMiddleware.ensureRole([RoleUsuario.ADMIN, RoleUsuario.FUNCIONARIO]), // 2. Tem permissão?
  adminRoutes
);

// ... (Restante do seu app.js)

export default app;
```

## 🛡️ API do Pacote

Ao chamar `createAuthModule`, você recebe um objeto com duas propriedades principais:

### `authRoutes`

Um `Router` do Express que você deve montar com `app.use()`. Ele expõe as seguintes rotas:

| Método  | Rota                      | Protegida? | Descrição                                                              |
| :------ | :------------------------ | :--------- | :--------------------------------------------------------------------- |
| `POST`  | `/register`               | Não        | Registra um novo usuário.                                              |
| `POST`  | `/login`                  | Não        | Efetua login e retorna `accessToken` (body) e `refreshToken` (cookie). |
| `POST`  | `/refresh-token`          | Não        | Usa o `refreshToken` (do cookie) para emitir um novo `accessToken`.    |
| `POST`  | `/request-password-reset` | Não        | Envia um email de redefinição de senha.                                |
| `POST`  | `/reset-password`         | Não        | Define uma nova senha usando um token válido.                          |
| `GET`   | `/verify-email`           | Não        | Valida o token de verificação de email (link do email).                |
| `GET`   | `/verify-email-update`    | Não        | Valida o token de atualização de email (link do email).                |
| `POST`  | `/logout`                 | **Sim**    | Efetua logout (invalida o `refreshToken`).                             |
| `POST`  | `/request-email-update`   | **Sim**    | Inicia o fluxo de mudança de email (requer senha atual).               |
| `PATCH` | `/update-password`        | **Sim**    | Atualiza a senha do usuário logado (requer senha antiga).              |
| `GET`   | `/me`                     | **Sim**    | Rota de teste. Retorna os dados do `req.user` (id, email, cargo).      |

### `authMiddleware`

Um objeto contendo os middlewares para proteger suas rotas.

#### `authMiddleware.ensureAuthenticated`

Middleware que verifica o `Authorization: Bearer <token>` (Access Token). Ele valida o token, checa se o usuário ainda existe no banco e injeta `req.user = { id, email, cargo }`.

#### `authMiddleware.ensureRole(allowedRoles: RoleUsuario[])`

Um _construtor_ de middleware que deve ser usado _após_ `ensureAuthenticated`. Ele nega o acesso (403 Forbidden) se o `req.user.cargo` não estiver no array `allowedRoles`.

**Exemplo:**

```javascript
import { RoleUsuario } from "@prisma/client";

app.get(
  "/admin/rota-secreta",
  authMiddleware.ensureAuthenticated,
  authMiddleware.ensureRole([RoleUsuario.ADMIN]),
  adminController.getDadosSecretos
);
```

## 📄 Licença

Este projeto é distribuído sob a Licença MIT. Veja o arquivo [`LICENSE`](./LICENSE) para mais detalhes.

Copyright (c) 2025 [Joao Matheus de Oliveira Schmitz]
