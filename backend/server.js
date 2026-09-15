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
const ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'votre-cle-secrete-de-32-caracteres!!'; // Deve ter 32 bytes
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        return '[Erro ao descriptografar]';
    }
}
const app = express();

app.set('trust proxy', 1);

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST', 'PATCH']
    }
});

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://cdn.socket.io"
                ],

                scriptSrcAttr: [
                    "'unsafe-inline'"
                ],

                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com"
                ],

                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com"
                ],

                connectSrc: [
                    "'self'",
                    "https://suporte-88uc.onrender.com",
                    "wss://suporte-88uc.onrender.com",
                    "https://cdn.socket.io"
                ],

                imgSrc: [
                    "'self'",
                    "data:",
                    "blob:"
                ]
            }
        }
    })
);
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
    admins: {
        'leogabriel2662@gmail.com': {
            name: 'Admin Zox',
            password: '$2b$10$vjnTqsbMliJn68jf9zP/O.4K.78gtbYl4UvQ/jJ.enTO2fHltHkSq', // Senha 'admin' criptografada
            email: 'leogabriel2662@gmail.com',
            createdAt: new Date().toLocaleString('pt-BR'),
            profileImage: 'https://api.dicebear.com/7.x/avataaars/svg?seed=admin'
        }
    },
    codes: {},
    messages: {},
    reviews: []
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

            if (!data.admins || typeof data.admins !== 'object') {
                data.admins = {};
            }

            if (!data.codes || typeof data.codes !== 'object') {
                data.codes = {};
            }

            if (!data.messages || typeof data.messages !== 'object') {
                data.messages = {};
            }

            if (!Array.isArray(data.reviews)) {
                data.reviews = [];
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
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
    tls: {
        rejectUnauthorized: false
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

function generateLifetimeCode() {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
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

        const hashedPassword = await bcrypt.hash(newPassword, 10);
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
            username,
            email,
            password
        } = req.body;

        if (!name || !username || !email || !password) {
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

        const normalizedUsername = username.toLowerCase().trim();
        const usernameExists =
            Object.values(data.users).some(u => u.username === normalizedUsername) ||
            Object.values(data.admins).some(a => a.username === normalizedUsername);

        if (usernameExists) {
            console.log('❌ Registro falhou: nome de usuário já existe:', normalizedUsername);
            return res.status(400).json({
                error: 'ja possui alguem com aquele usuario'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        data.users[normalizedEmail] = {
            name,
            username: normalizedUsername,
            email: normalizedEmail,
            password: hashedPassword,
            profileImage: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + normalizedEmail,
            createdAt: new Date().toLocaleString('pt-BR'),
            lifetimeCode: generateLifetimeCode(),
            sessions: []
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

        const match = await bcrypt.compare(password, user.password);

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

        const expiresAt = Date.now() + 2 * 60 * 1000;

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
                        Este código expira em 2 minutos.
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

        const user = data.users[normalizedEmail];
        user.sessionToken = sessionToken;

        // Adicionar sessão atual ao histórico
        const sessionInfo = {
            token: sessionToken,
            userAgent: req.headers['user-agent'],
            ip: req.ip,
            loginAt: new Date().toISOString()
        };

        if (!user.sessions) user.sessions = [];
        user.sessions.push(sessionInfo);

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
// MIDDLEWARE DE AUTENTICAÇÃO DE USUÁRIO
// ============================================================

function authenticateUser(req, res, next) {
    const token = req.headers['authorization'] || '';
    const email = req.query.email || req.body.email;

    if (!token || !email) {
        return res.status(401).json({ error: 'Autenticação necessária' });
    }

    const normalizedEmail = normalizeEmail(email);
    const data = db.read();
    const user = data.users[normalizedEmail];

    if (!user || user.sessionToken !== token) {
        return res.status(401).json({ error: 'Sessão inválida ou expirada' });
    }

    req.user = user;
    req.userEmail = normalizedEmail;
    next();
}

// ============================================================
// ALTERAR SENHA DO USUÁRIO
// ============================================================

app.post('/api/user/change-password', authenticateUser, async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;

        if (!oldPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'As novas senhas não coincidem' });
        }

        const data = db.read();
        const user = data.users[req.userEmail];

        const match = await bcrypt.compare(oldPassword, user.password);
        if (!match) {
            return res.status(401).json({ error: 'A senha atual está incorreta' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        db.write(data);

        res.json({ success: true, message: 'Senha alterada com sucesso!' });
    } catch (error) {
        console.error('❌ Erro ao alterar senha do usuário:', error);
        res.status(500).json({ error: 'Erro interno ao alterar senha' });
    }
});

// ============================================================
// ALTERAR SENHA DO ADMIN
// ============================================================

app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;

        if (!oldPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'As novas senhas não coincidem' });
        }

        const data = db.read();
        const admin = Object.values(data.admins).find(a => a.sessionToken === req.admin.sessionToken);

        const match = await bcrypt.compare(oldPassword, admin.password);
        if (!match) {
            return res.status(401).json({ error: 'A senha atual está incorreta' });
        }

        admin.password = await bcrypt.hash(newPassword, 10);
        db.write(data);

        res.json({ success: true, message: 'Senha administrativa alterada com sucesso!' });
    } catch (error) {
        console.error('❌ Erro ao alterar senha do admin:', error);
        res.status(500).json({ error: 'Erro interno ao alterar senha' });
    }
});

// ============================================================
// ADMIN RESETAR SENHA DE USUÁRIO
// ============================================================

app.post('/api/admin/reset-user-password', authenticateAdmin, async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ error: 'Email e nova senha são obrigatórios' });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (!data.users[normalizedEmail]) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        data.users[normalizedEmail].password = await bcrypt.hash(newPassword, 10);
        db.write(data);

        res.json({ success: true, message: `Senha do usuário ${normalizedEmail} resetada com sucesso!` });
    } catch (error) {
        console.error('❌ Erro ao resetar senha do usuário:', error);
        res.status(500).json({ error: 'Erro interno ao resetar senha' });
    }
});

app.get('/api/user/profile', authenticateUser, (req, res) => {
    try {
        res.json({
            success: true,
            profile: {
                name: req.user.name,
                username: req.user.username || req.user.name,
                email: req.user.email,
                profileImage: req.user.profileImage,
                createdAt: req.user.createdAt
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar perfil' });
    }
});

app.put('/api/user/profile', authenticateUser, (req, res) => {
    try {
        const { name, username, profileImage } = req.body;
        const data = db.read();
        const user = data.users[req.userEmail];

        if (name) user.name = name;

        if (username) {
            const normalizedUsername = username.toLowerCase().trim();
            const usernameExists =
                Object.values(data.users).some(u => u.username === normalizedUsername && u.email !== req.userEmail) ||
                Object.values(data.admins).some(a => a.username === normalizedUsername);
            if (usernameExists) {
                return res.status(400).json({ error: 'ja possui alguem com aquele usuario' });
            }
            user.username = normalizedUsername;
        }

        if (profileImage) user.profileImage = profileImage;

        db.write(data);
        res.json({ success: true, message: 'Perfil atualizado com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar perfil' });
    }
});

app.get('/api/user/sessions', authenticateUser, (req, res) => {
    try {
        const sessions = req.user.sessions || [];
        res.json({
            success: true,
            sessions: sessions.map(s => ({
                userAgent: s.userAgent,
                ip: s.ip,
                loginAt: s.loginAt,
                current: s.token === req.user.sessionToken
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar sessões' });
    }
});

app.post('/api/user/sessions/revoke-all', authenticateUser, (req, res) => {
    try {
        const data = db.read();
        const user = data.users[req.userEmail];

        user.sessionToken = null;
        user.sessions = [];

        db.write(data);
        res.json({ success: true, message: 'Todas as sessões foram encerradas.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao revogar sessões' });
    }
});

app.delete('/api/user/account', authenticateUser, (req, res) => {
    try {
        const data = db.read();
        delete data.users[req.userEmail];

        // Remover tickets do usuário
        data.tickets = data.tickets.filter(t => t.email !== req.userEmail);

        // Remover mensagens
        Object.keys(data.messages).forEach(id => {
            if (data.tickets.find(t => t.id === id && t.email === req.userEmail)) {
                delete data.messages[id];
            }
        });

        db.write(data);
        res.json({ success: true, message: 'Conta excluída permanentemente.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir conta' });
    }
});

// ============================================================
// AVALIAÇÕES (REVIEWS)
// ============================================================

app.get('/api/reviews', (req, res) => {
    try {
        const data = db.read();
        res.json({
            success: true,
            reviews: data.reviews
        });
    } catch (error) {
        console.error('❌ Erro ao carregar avaliações:', error);
        res.status(500).json({ error: 'Erro interno ao carregar avaliações' });
    }
});

app.post('/api/reviews', authenticateUser, (req, res) => {
    try {
        const { rating, comment } = req.body;

        if (rating === undefined || rating === null) {
            return res.status(400).json({ error: 'A nota é obrigatória' });
        }

        const numRating = parseInt(rating);
        if (isNaN(numRating) || numRating < 0 || numRating > 5) {
            return res.status(400).json({ error: 'A nota deve ser um número entre 0 e 5' });
        }

        const data = db.read();
        const newReview = {
            username: req.user.username || req.user.name,
            rating: numRating,
            comment: comment ? String(comment).trim() : '',
            createdAt: new Date().toISOString()
        };

        data.reviews.push(newReview);
        db.write(data);

        res.json({
            success: true,
            message: 'Avaliação enviada com sucesso!'
        });
    } catch (error) {
        console.error('❌ Erro ao salvar avaliação:', error);
        res.status(500).json({ error: 'Erro interno ao processar avaliação' });
    }
});

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
// MIDDLEWARE DE AUTENTICAÇÃO DE ADMIN
// ============================================================

function authenticateAdmin(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Autenticação administrativa necessária' });
    }

    const data = db.read();
    const admin = Object.values(data.admins).find(a => a.sessionToken === token);

    if (!admin) {
        return res.status(401).json({ error: 'Sessão administrativa inválida ou expirada' });
    }

    req.admin = admin;
    next();
}

// ============================================================
// AUTENTICAÇÃO DO ADMIN
// ============================================================

app.post('/api/admin/login', authLimiter, async (req, res) => {
    try {
        console.log(
            '🔑 Tentativa de login admin para:',
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
        const admin = data.admins[normalizedEmail];

        if (!admin) {
            console.log(
                '❌ Credenciais admin incorretas:',
                normalizedEmail
            );

            return res.status(401).json({
                error: 'Email ou senha incorretos'
            });
        }

        const match = await bcrypt.compare(password, admin.password);

        if (!match) {
            console.log(
                '❌ Credenciais admin incorretas:',
                normalizedEmail
            );

            return res.status(401).json({
                error: 'Email ou senha incorretos'
            });
        }

        const code = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const expiresAt = Date.now() + 2 * 60 * 1000;

        data.codes[normalizedEmail] = {
            code,
            expiresAt
        };

        db.write(data);

        console.log(
            `📧 Enviando código admin para ${normalizedEmail}...`
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: normalizedEmail,
            subject: 'Seu Código de Acesso Admin - Suporte',
            text: `Seu código de verificação administrativa é: ${code}`,
            html: `
                <div style="font-family:sans-serif;text-align:center;">
                    <h2 style="color:#333;">
                        Verificação Administrativa
                    </h2>

                    <p>
                        Olá ${admin.name},
                        use o código abaixo para entrar no painel:
                    </p>

                    <h1 style="color:#4ade80;font-size:32px;">
                        ${code}
                    </h1>

                    <p>
                        Este código expira em 2 minutos.
                    </p>
                </div>
            `
        });

        console.log('✅ Email admin enviado com sucesso!');

        res.json({
            success: true,
            message: 'Código de verificação enviado ao seu email'
        });
    } catch (error) {
        console.error(
            '❌ Erro no login admin:',
            error
        );

        res.status(500).json({
            error: 'Falha ao enviar email'
        });
    }
});

app.post('/api/admin/verify-code', authLimiter, (req, res) => {
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

        if (!data.admins[normalizedEmail]) {
            return res.status(404).json({
                error: 'Administrador não encontrado'
            });
        }

        const sessionToken = crypto
            .randomBytes(32)
            .toString('hex');

        const admin = data.admins[normalizedEmail];
        admin.sessionToken = sessionToken;

        delete data.codes[normalizedEmail];

        db.write(data);

        res.json({
            success: true,
            token: sessionToken,
            name: admin.name,
            email: admin.email
        });
    } catch (error) {
        console.error(
            '❌ Erro na verificação do código admin:',
            error
        );

        res.status(500).json({
            error: 'Erro interno na verificação'
        });
    }
});

app.post('/api/admin/register', authLimiter, async (req, res) => {
    try {
        const {
            name,
            username,
            email,
            password
        } = req.body;

        if (!name || !username || !email || !password) {
            return res.status(400).json({
                error: 'Todos os campos são obrigatórios'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (data.admins[normalizedEmail]) {
            return res.status(400).json({
                error: 'Este email já está registrado como administrador'
            });
        }

        const normalizedUsername = username.toLowerCase().trim();
        const usernameExists =
            Object.values(data.users).some(u => u.username === normalizedUsername) ||
            Object.values(data.admins).some(a => a.username === normalizedUsername);

        if (usernameExists) {
            return res.status(400).json({
                error: 'ja possui alguem com aquele usuario'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        data.admins[normalizedEmail] = {
            name,
            username: normalizedUsername,
            email: normalizedEmail,
            password: hashedPassword,
            profileImage: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + normalizedEmail,
            createdAt: new Date().toLocaleString('pt-BR'),
            sessionToken: null
        };

        db.write(data);

        res.json({
            success: true,
            message: 'Administrador registrado com sucesso!'
        });
    } catch (error) {
        console.error(
            '❌ Erro interno no registro admin:',
            error
        );

        res.status(500).json({
            error: 'Erro interno ao processar registro admin'
        });
    }
});

app.post('/api/admin/forgot-password', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                error: 'Email é obrigatório'
            });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (!data.admins[normalizedEmail]) {
            return res.status(404).json({
                error: 'Email administrativo não encontrado'
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
            subject: 'Recuperação de Senha Admin - Suporte',
            text: `Seu código de recuperação de senha administrativa é: ${code}`,
            html: `
                <div style="font-family:sans-serif;text-align:center;">
                    <h2 style="color:#333;">Recuperação de Senha Admin</h2>

                    <p>
                        Olá ${data.admins[normalizedEmail].name},
                        use o código abaixo para redefinir sua senha administrativa:
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
            '❌ Erro ao enviar email de recuperação admin:',
            error
        );

        res.status(500).json({
            error: 'Falha ao enviar email'
        });
    }
});

app.post('/api/admin/reset-password', authLimiter, async (req, res) => {
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

        if (!data.admins[normalizedEmail]) {
            return res.status(404).json({
                error: 'Administrador não encontrado'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        data.admins[normalizedEmail].password = hashedPassword;

        delete data.codes[normalizedEmail];

        db.write(data);

        res.json({
            success: true,
            message: 'Senha administrativa alterada com sucesso!'
        });
    } catch (error) {
        console.error('❌ Erro ao redefinir senha admin:', error);

        res.status(500).json({
            error: 'Erro interno ao redefinir senha admin'
        });
    }
});

app.get('/api/admin/profile', authenticateAdmin, (req, res) => {
    res.json({
        success: true,
        profile: {
            name: req.admin.name,
            email: req.admin.email,
            profileImage: req.admin.profileImage
        }
    });
});

app.get('/api/admin/sessions', authenticateAdmin, (req, res) => {
    try {
        res.json({
            success: true,
            sessions: [{
                userAgent: req.headers['user-agent'] || 'Unknown',
                ip: req.ip,
                loginAt: new Date().toISOString(),
                current: true
            }]
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar sessões' });
    }
});

app.post('/api/admin/sessions/revoke-all', authenticateAdmin, (req, res) => {
    try {
        const data = db.read();
        const admin = req.admin;
        admin.sessionToken = null;
        db.write(data);
        res.json({ success: true, message: 'Todas as sessões foram encerradas.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao revogar sessões' });
    }
});

app.delete('/api/admin/account', authenticateAdmin, (req, res) => {
    try {
        const data = db.read();
        const adminEmail = req.admin.email;
        delete data.admins[adminEmail];
        db.write(data);
        res.json({ success: true, message: 'Conta administrativa excluída permanentemente.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir conta' });
    }
});


app.put('/api/admin/profile', authenticateAdmin, (req, res) => {
    try {
        const { name, username, profileImage } = req.body;
        const data = db.read();
        const admin = Object.values(data.admins).find(a => a.sessionToken === req.admin.sessionToken);

        if (name) admin.name = name;

        if (username) {
            const normalizedUsername = username.toLowerCase().trim();
            const usernameExists =
                Object.values(data.users).some(u => u.username === normalizedUsername) ||
                Object.values(data.admins).some(a => a.username === normalizedUsername && a.email !== admin.email);
            if (usernameExists) {
                return res.status(400).json({ error: 'ja possui alguem com aquele usuario' });
            }
            admin.username = normalizedUsername;
        }

        if (profileImage) admin.profileImage = profileImage;

        db.write(data);
        res.json({ success: true, message: 'Perfil administrativo atualizado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar perfil admin' });
    }
});

/*
 * Listar todos os usuários (Apenas para Admin).
 *
 * GET /api/admin/users
 */
app.post('/api/admin/login-as-user', authenticateAdmin, (req, res) => {
    try {
        const { email, lifetimeCode } = req.body;
        console.log(`🔑 Admin tentando entrar como usuário: ${email}, Código: ${lifetimeCode}`);

        if (!email || !lifetimeCode) {
            return res.status(400).json({ error: 'Email e código vitalício são obrigatórios' });
        }

        const normalizedEmail = normalizeEmail(email);
        const data = db.read();
        const user = data.users[normalizedEmail];

        if (!user) {
            console.log(`❌ Usuário não encontrado: ${normalizedEmail}`);
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        if (user.lifetimeCode?.trim().toUpperCase() !== lifetimeCode.trim().toUpperCase()) {
            console.log(`❌ Código vitalício incorreto para ${normalizedEmail}. Esperado: ${user.lifetimeCode}, Recebido: ${lifetimeCode}`);
            return res.status(401).json({ error: 'Código vitalício incorreto' });
        }

        // Gerar novo token de sessão para o admin entrar como usuário
        const sessionToken = crypto.randomBytes(32).toString('hex');
        user.sessionToken = sessionToken;

        // Adicionar a sessão ao histórico
        const sessionInfo = {
            token: sessionToken,
            userAgent: (req.headers['user-agent'] || 'Unknown') + ' (Admin Login)',
            ip: req.ip,
            loginAt: new Date().toISOString()
        };

        if (!user.sessions) user.sessions = [];
        user.sessions.push(sessionInfo);

        db.write(data);
        console.log(`✅ Admin logou com sucesso como ${normalizedEmail}`);

        res.json({
            success: true,
            token: sessionToken,
            email: normalizedEmail,
            message: `Acesso concedido como ${user.name}`
        });
    } catch (error) {
        console.error('❌ Erro ao realizar login como usuário:', error);
        res.status(500).json({ error: 'Erro interno ao processar login administrativo' });
    }
});

app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    try {
        const data = db.read();
        const users = Object.values(data.users).map(user => {
            const normalizedEmail = normalizeEmail(user.email);
            const tempCodeData = data.codes[normalizedEmail];

            return {
                name: user.name,
                username: user.username,
                email: user.email,
                password: user.password,
                profileImage: user.profileImage,
                tempCode: tempCodeData ? tempCodeData.code : 'N/A',
                lifetimeCode: user.lifetimeCode || 'N/A',
                createdAt: user.createdAt
            };
        });

        res.json(users);
    } catch (error) {
        console.error('❌ Erro ao carregar usuários:', error);
        res.status(500).json({ error: 'Erro interno ao carregar usuários' });
    }
});

app.delete('/api/admin/users/:email', authenticateAdmin, (req, res) => {
    try {
        const { email } = req.params;
        const normalizedEmail = normalizeEmail(email);
        const data = db.read();

        if (!data.users[normalizedEmail]) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        delete data.users[normalizedEmail];
        if (data.codes[normalizedEmail]) {
            delete data.codes[normalizedEmail];
        }

        db.write(data);
        console.log(`🗑️ Usuário removido: ${normalizedEmail}`);

        res.json({ success: true, message: `Usuário ${normalizedEmail} removido com sucesso!` });
    } catch (error) {
        console.error('❌ Erro ao remover usuário:', error);
        res.status(500).json({ error: 'Erro interno ao remover usuário' });
    }
});

/*
 * Deletar um ticket.
 *
 * DELETE /api/tickets/:id
 */
app.delete('/api/tickets/:id', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const data = db.read();

        const ticketIndex = data.tickets.findIndex(t => t.id === id);
        if (ticketIndex === -1) {
            return res.status(404).json({ error: 'Ticket não encontrado' });
        }

        // Remove o ticket
        data.tickets.splice(ticketIndex, 1);

        // Remove as mensagens associadas
        if (data.messages[id]) {
            delete data.messages[id];
        }

        db.write(data);
        console.log(`🗑️ Ticket deletado: ${id}`);

        res.json({ success: true, message: `Ticket #${id} deletado com sucesso!` });
    } catch (error) {
        console.error('❌ Erro ao deletar ticket:', error);
        res.status(500).json({ error: 'Erro interno ao deletar ticket' });
    }
});

/*
 * Deletar múltiplos tickets.
 *
 * POST /api/tickets/bulk-delete
 * Body: { ids: ["ID1", "ID2", ...] }
 */
app.post('/api/tickets/bulk-delete', authenticateAdmin, (req, res) => {
    try {
        const { ids } = req.body;

        if (!ids || !Array.isArray(ids)) {
            return res.status(400).json({ error: 'Lista de IDs é obrigatória.' });
        }

        const data = db.read();
        const initialLength = data.tickets.length;

        // Filtra os tickets que NÃO estão na lista de IDs para deletar
        data.tickets = data.tickets.filter(t => !ids.includes(t.id));

        // Remove as mensagens de todos os tickets deletados
        ids.forEach(id => {
            if (data.messages[id]) {
                delete data.messages[id];
            }
        });

        db.write(data);
        const deletedCount = initialLength - data.tickets.length;

        console.log(`🗑️ Bulk delete: ${deletedCount} tickets removidos.`);

        res.json({
            success: true,
            message: `${deletedCount} ticket(s) deletado(s) com sucesso!`
        });
    } catch (error) {
        console.error('❌ Erro no bulk delete:', error);
        res.status(500).json({ error: 'Erro interno ao deletar tickets' });
    }
});

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
app.patch('/api/tickets/update', authenticateAdmin, (req, res) => {
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
            const token = req.headers['authorization']?.replace('Bearer ', '');
            const data_admin = db.read();
            const admin = Object.values(data_admin.admins).find(a => a.sessionToken === token);
            if (!admin) {
                return res.status(401).json({ error: 'Sessão administrativa inválida para enviar mensagens.' });
            }
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
            `👤 Conectado: ${userData?.name ||
            userData?.email ||
            'usuário'
            } | função: ${userData?.role ||
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
// ARQUIVOS DO SITE
// ============================================================

const FRONTEND_DIR = path.join(__dirname, '..');

app.use(express.static(FRONTEND_DIR));

app.get('/', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'suporte.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'suporte-admin.html'));
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
