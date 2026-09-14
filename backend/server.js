require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST', 'PATCH']
    }
});

app.use(helmet());
app.use(cors());

/*
 * Aumentado para permitir anexos enviados em Base64.
 * Se você não usa arquivos grandes, pode reduzir depois.
 */
app.use(express.json({ limit: '15mb' }));

// ============================================================
// RATE LIMIT - AUTENTICAÇÃO
// ============================================================

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        error: 'Muitas tentativas. Tente novamente em 15 minutos.'
    }
});

// ============================================================
// DATABASE
// ============================================================

const DB_FILE = path.join(__dirname, 'database.json');

const createEmptyDatabase = () => ({
    tickets: [],
    users: {},
    codes: {},
    messages: {}
});

const db = {
    read: () => {
        try {
            if (!fs.existsSync(DB_FILE)) {
                const empty = createEmptyDatabase();
                fs.writeFileSync(
                    DB_FILE,
                    JSON.stringify(empty, null, 2)
                );
                return empty;
            }

            const raw = fs.readFileSync(DB_FILE, 'utf8');

            if (!raw.trim()) {
                return createEmptyDatabase();
            }

            const data = JSON.parse(raw);

            if (!Array.isArray(data.tickets)) {
                data.tickets = [];
            }

            if (!data.users || typeof data.users !== 'object') {
                data.users = {};
            }

            if (!data.codes || typeof data.codes !== 'object') {
                data.codes = {};
            }

            if (!data.messages || typeof data.messages !== 'object') {
                data.messages = {};
            }

            return data;
        } catch (error) {
            console.error('❌ Erro ao ler database.json:', error);
            throw error;
        }
    },

    write: (data) => {
        try {
            fs.writeFileSync(
                DB_FILE,
                JSON.stringify(data, null, 2)
            );
        } catch (error) {
            console.error('❌ Erro ao salvar database.json:', error);
            throw error;
        }
    }
};

// ============================================================
// EMAIL
// ============================================================

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// ============================================================
// FUNÇÕES AUXILIARES
// ============================================================

function normalizeEmail(email) {
    return String(email || '').toLowerCase().trim();
}

function generateTicketId(existingTickets) {
    let id;

    do {
        id = `SUPP-${new Date().getFullYear()}-${Math.floor(
            Math.random() * 10000
        ).toString().padStart(4, '0')}`;
    } while (existingTickets.some(ticket => ticket.id === id));

    return id;
}

function isValidTicketStatus(status) {
    return ['open', 'pending', 'closed'].includes(status);
}

// ============================================================
// AUTENTICAÇÃO DO CLIENTE
// ============================================================

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                error: 'Email é obrigatório'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (!data.users[normalizedEmail]) {
            return res.status(404).json({
                error: 'Email não encontrado'
            });
        }

        const code = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const expiresAt = Date.now() + 15 * 60 * 1000;

        data.codes[normalizedEmail] = {
            code,
            expiresAt
        };

        db.write(data);

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: normalizedEmail,
            subject: 'Recuperação de Senha - Suporte',
            text: `Seu código de recuperação de senha é: ${code}`,
            html: `
                <div style="font-family:sans-serif;text-align:center;">
                    <h2 style="color:#333;">Recuperação de Senha</h2>

                    <p>
                        Olá ${data.users[normalizedEmail].name},
                        use o código abaixo para redefinir sua senha:
                    </p>

                    <h1 style="color:#4ade80;font-size:32px;">
                        ${code}
                    </h1>

                    <p>
                        Este código expira em 15 minutos.
                    </p>
                </div>
            `
        });

        res.json({
            success: true,
            message: 'Código de recuperação enviado ao seu email!'
        });

    } catch (error) {
        console.error(
            '❌ Erro ao enviar email de recuperação:',
            error
        );

        res.status(500).json({
            error: 'Falha ao enviar email'
        });
    }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
    try {
        const {
            email,
            code,
            newPassword
        } = req.body;

        if (!email || !code || !newPassword) {
            return res.status(400).json({
                error: 'Todos os campos são obrigatórios'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();
        const storedCode = data.codes[normalizedEmail];

        if (
            !storedCode ||
            storedCode.code !== code ||
            Date.now() > storedCode.expiresAt
        ) {
            return res.status(400).json({
                error: 'Código inválido ou expirado'
            });
        }

        if (!data.users[normalizedEmail]) {
            return res.status(404).json({
                error: 'Usuário não encontrado'
            });
        }

        const hashedPassword = await bcrypt.hash(
            newPassword,
            10
        );

        data.users[normalizedEmail].password = hashedPassword;

        delete data.codes[normalizedEmail];

        db.write(data);

        res.json({
            success: true,
            message: 'Senha alterada com sucesso!'
        });

    } catch (error) {
        console.error('❌ Erro ao redefinir senha:', error);

        res.status(500).json({
            error: 'Erro interno ao redefinir senha'
        });
    }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        console.log(
            '📩 Recebendo requisição de registro:',
            req.body
        );

        const {
            name,
            email,
            password
        } = req.body;

        if (!name || !email || !password) {
            console.log(
                '❌ Registro falhou: campos ausentes'
            );

            return res.status(400).json({
                error: 'Todos os campos são obrigatórios'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (data.users[normalizedEmail]) {
            console.log(
                '❌ Registro falhou: email já existe:',
                normalizedEmail
            );

            return res.status(400).json({
                error: 'Este email já está registrado'
            });
        }

        const hashedPassword = await bcrypt.hash(
            password,
            10
        );

        data.users[normalizedEmail] = {
            name,
            email: normalizedEmail,
            password: hashedPassword,
            createdAt: new Date().toLocaleString('pt-BR')
        };

        db.write(data);

        console.log(
            '✅ Usuário registrado com sucesso:',
            normalizedEmail
        );

        res.json({
            success: true,
            message: 'Usuário registrado com sucesso!'
        });

    } catch (error) {
        console.error(
            '❌ Erro interno no registro:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao processar registro'
        });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        console.log(
            '🔑 Tentativa de login para:',
            req.body.email
        );

        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: 'Email e senha são obrigatórios'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();
        const user = data.users[normalizedEmail];

        if (!user) {
            console.log(
                '❌ Usuário não encontrado:',
                normalizedEmail
            );

            return res.status(401).json({
                error: 'Email ou senha incorretos'
            });
        }

        const match = await bcrypt.compare(
            password,
            user.password
        );

        if (!match) {
            console.log(
                '❌ Senha incorreta:',
                normalizedEmail
            );

            return res.status(401).json({
                error: 'Email ou senha incorretos'
            });
        }

        const code = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const expiresAt = Date.now() + 5 * 60 * 1000;

        data.codes[normalizedEmail] = {
            code,
            expiresAt
        };

        db.write(data);

        console.log(
            `📧 Enviando código para ${normalizedEmail}...`
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: normalizedEmail,
            subject: 'Seu Código de Acesso - Suporte',
            text: `Seu código de verificação é: ${code}`,
            html: `
                <div style="font-family:sans-serif;text-align:center;">
                    <h2 style="color:#333;">
                        Verificação de Segurança
                    </h2>

                    <p>
                        Olá ${user.name},
                        use o código abaixo para entrar:
                    </p>

                    <h1 style="color:#4ade80;font-size:32px;">
                        ${code}
                    </h1>

                    <p>
                        Este código expira em 5 minutos.
                    </p>
                </div>
            `
        });

        console.log('✅ Email enviado com sucesso!');

        res.json({
            success: true,
            message: 'Código de verificação enviado ao seu email'
        });

    } catch (error) {
        console.error(
            '❌ Erro ao enviar email:',
            error
        );

        res.status(500).json({
            error: 'Falha ao enviar email'
        });
    }
});

app.post('/api/auth/verify-code', authLimiter, (req, res) => {
    try {
        const {
            email,
            code
        } = req.body;

        if (!email || !code) {
            return res.status(400).json({
                error: 'Email e código são obrigatórios'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();
        const storedCode = data.codes[normalizedEmail];

        if (
            !storedCode ||
            storedCode.code !== code ||
            Date.now() > storedCode.expiresAt
        ) {
            return res.status(400).json({
                error: 'Código inválido ou expirado'
            });
        }

        if (!data.users[normalizedEmail]) {
            return res.status(404).json({
                error: 'Usuário não encontrado'
            });
        }

        const sessionToken = crypto
            .randomBytes(32)
            .toString('hex');

        data.users[normalizedEmail].sessionToken =
            sessionToken;

        delete data.codes[normalizedEmail];

        db.write(data);

        res.json({
            success: true,
            token: sessionToken
        });

    } catch (error) {
        console.error(
            '❌ Erro na verificação do código:',
            error
        );

        res.status(500).json({
            error: 'Erro interno na verificação'
        });
    }
});

// ============================================================
// TICKETS - CLIENTE
// ============================================================

app.post('/api/tickets/create', (req, res) => {
    try {
        const {
            name,
            email,
            category,
            project,
            title,
            description,
            attachments
        } = req.body;

        if (
            !name ||
            !email ||
            !category ||
            !title ||
            !description
        ) {
            return res.status(400).json({
                error: 'Nome, email, categoria, título e descrição são obrigatórios.'
            });
        }

        const data = db.read();

        const normalizedEmail = normalizeEmail(email);

        const newTicket = {
            id: generateTicketId(data.tickets),

            name: String(name).trim(),

            email: normalizedEmail,

            category: String(category).trim(),

            project: project
                ? String(project).trim()
                : '',

            title: String(title).trim(),

            description: String(description).trim(),

            attachments: Array.isArray(attachments)
                ? attachments
                : [],

            status: 'open',

            createdAt: new Date().toISOString()
        };

        data.tickets.push(newTicket);

        db.write(data);

        console.log(
            `🎫 Novo ticket criado: ${newTicket.id} | ${newTicket.title}`
        );

        /*
         * Aviso em tempo real para o painel admin.
         */
        io.emit('new-ticket', newTicket);

        /*
         * Mantido também para compatibilidade
         * com painéis que escutam ticket-created.
         */
        io.emit('ticket-created', newTicket);

        res.status(201).json({
            success: true,
            ticket: newTicket
        });

    } catch (error) {
        console.error(
            '❌ Erro ao criar ticket:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao criar ticket'
        });
    }
});

// ============================================================
// TICKETS - ADMIN
//
// IMPORTANTE:
// Estas rotas NÃO usam isAdmin.
// O painel administrativo não possui login.
// ============================================================

/*
 * Listar todos os tickets.
 *
 * GET /api/tickets
 */
app.get('/api/tickets', (req, res) => {
    try {
        const data = db.read();

        /*
         * Mais recentes primeiro.
         */
        const tickets = [...data.tickets].reverse();

        res.json(tickets);

    } catch (error) {
        console.error(
            '❌ Erro ao carregar tickets:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao carregar tickets'
        });
    }
});

/*
 * Assumir / atualizar / fechar ticket.
 *
 * PATCH /api/tickets/update
 *
 * Exemplos:
 *
 * {
 *   "id": "SUPP-2026-1234",
 *   "status": "pending"
 * }
 *
 * ou
 *
 * {
 *   "id": "SUPP-2026-1234",
 *   "status": "closed"
 * }
 */
app.patch('/api/tickets/update', (req, res) => {
    try {
        const {
            id,
            status
        } = req.body;

        if (!id || !status) {
            return res.status(400).json({
                error: 'ID e status são obrigatórios.'
            });
        }

        if (!isValidTicketStatus(status)) {
            return res.status(400).json({
                error: 'Status inválido. Use: open, pending ou closed.'
            });
        }

        const data = db.read();

        const ticket = data.tickets.find(
            ticket => ticket.id === id
        );

        if (!ticket) {
            return res.status(404).json({
                error: 'Ticket não encontrado'
            });
        }

        const oldStatus = ticket.status;

        ticket.status = status;

        /*
         * Registra quando houve atualização.
         */
        ticket.updatedAt = new Date().toISOString();

        db.write(data);

        console.log(
            `🔄 Ticket atualizado: ${ticket.id} | ${oldStatus} → ${status}`
        );

        io.emit('ticket-updated', ticket);

        res.json({
            success: true,
            ticket
        });

    } catch (error) {
        console.error(
            '❌ Erro ao atualizar ticket:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao atualizar ticket'
        });
    }
});

// ============================================================
// CHAT - BUSCAR MENSAGENS
// ============================================================

/*
 * GET /api/tickets/:id/messages
 *
 * ADMIN:
 * Pode acessar sem login.
 *
 * CLIENTE:
 * Precisa enviar o email correspondente ao ticket.
 */
app.get('/api/tickets/:id/messages', (req, res) => {
    try {
        const {
            id
        } = req.params;

        const email = normalizeEmail(
            req.query.email
        );

        const data = db.read();

        const ticket = data.tickets.find(
            ticket => ticket.id === id
        );

        if (!ticket) {
            return res.status(404).json({
                error: 'Ticket não encontrado'
            });
        }

        /*
         * O painel admin não envia email.
         *
         * Se houver email na query, tratamos como
         * acesso do cliente e validamos.
         *
         * Sem email:
         * acesso do painel admin.
         */
        if (
            email &&
            ticket.email !== email
        ) {
            return res.status(403).json({
                error: 'Acesso negado ao chat.'
            });
        }

        res.json(
            data.messages[id] || []
        );

    } catch (error) {
        console.error(
            '❌ Erro ao carregar mensagens:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao carregar mensagens'
        });
    }
});

// ============================================================
// CHAT - ENVIAR MENSAGEM
// ============================================================

/*
 * POST /api/tickets/:id/messages
 *
 * ADMIN:
 * {
 *   sender: "admin",
 *   text: "Olá..."
 * }
 *
 * CLIENTE:
 * {
 *   sender: "user",
 *   email: "cliente@email.com",
 *   text: "..."
 * }
 */
app.post('/api/tickets/:id/messages', (req, res) => {
    try {
        const {
            id
        } = req.params;

        const {
            sender,
            text,
            file,
            fileName,
            fileType,
            email
        } = req.body;

        const data = db.read();

        const ticket = data.tickets.find(
            ticket => ticket.id === id
        );

        if (!ticket) {
            return res.status(404).json({
                error: 'Ticket não encontrado'
            });
        }

        if (
            sender !== 'admin' &&
            sender !== 'user'
        ) {
            return res.status(400).json({
                error: 'Remetente inválido.'
            });
        }

        /*
         * Mensagem do cliente.
         *
         * Aqui mantemos a proteção por email.
         */
        if (sender === 'user') {
            const normalizedEmail = normalizeEmail(email);

            if (
                !normalizedEmail ||
                ticket.email !== normalizedEmail
            ) {
                return res.status(403).json({
                    error: 'Você não tem permissão para enviar mensagens neste ticket.'
                });
            }
        }

        /*
         * Mensagem do ADMIN.
         *
         * Não exige token porque o painel admin
         * não possui login.
         */
        if (sender === 'admin') {
            console.log(
                `💬 Admin respondeu ao ticket ${id}`
            );
        }

        /*
         * Evita mensagens completamente vazias,
         * mas permite mensagem contendo apenas arquivo.
         */
        const hasText =
            typeof text === 'string' &&
            text.trim().length > 0;

        const hasFile =
            Boolean(file);

        if (!hasText && !hasFile) {
            return res.status(400).json({
                error: 'A mensagem não pode estar vazia.'
            });
        }

        if (!data.messages[id]) {
            data.messages[id] = [];
        }

        const message = {
            sender,
            text: hasText ? text.trim() : '',
            file: file || null,
            fileName: fileName || null,
            fileType: fileType || null,
            timestamp: new Date().toISOString()
        };

        data.messages[id].push(message);

        db.write(data);

        /*
         * Atualiza atividade do ticket.
         */
        ticket.updatedAt = new Date().toISOString();

        /*
         * Não muda automaticamente o status quando
         * o admin responde.
         *
         * O status continua sendo controlado por:
         * PATCH /api/tickets/update
         */
        db.write(data);

        io.emit('ticket-message', {
            ticketId: id,
            message
        });

        res.json({
            success: true,
            message
        });

    } catch (error) {
        console.error(
            '❌ Erro ao enviar mensagem:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao enviar mensagem'
        });
    }
});

// ============================================================
// SOCKET.IO
// ============================================================

io.on('connection', (socket) => {
    console.log(
        `🔌 Socket conectado: ${socket.id}`
    );

    socket.on('identify', (userData) => {
        console.log(
            `👤 Conectado: ${
                userData?.name ||
                userData?.email ||
                'usuário'
            } | função: ${
                userData?.role ||
                'não informada'
            }`
        );
    });

    socket.on('disconnect', () => {
        console.log(
            `🔌 Socket desconectado: ${socket.id}`
        );
    });
});

// ============================================================
// TRATAMENTO DE ERROS
// ============================================================

app.use((req, res) => {
    res.status(404).json({
        error: 'Rota não encontrada',
        path: req.originalUrl
    });
});

app.use((error, req, res, next) => {
    console.error(
        '❌ Erro não tratado:',
        error
    );

    if (error instanceof SyntaxError) {
        return res.status(400).json({
            error: 'JSON inválido.'
        });
    }

    res.status(500).json({
        error: 'Erro interno do servidor.'
    });
});

// ============================================================
// SERVIDOR
// ============================================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log('');
    console.log('======================================');
    console.log('🚀 SERVIDOR DE SUPORTE ONLINE');
    console.log('======================================');
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`🎫 Tickets: /api/tickets`);
    console.log(`💬 Chat: /api/tickets/:id/messages`);
    console.log('🔌 Socket.IO: ativo');
    console.log('======================================');
    console.log('');
});
