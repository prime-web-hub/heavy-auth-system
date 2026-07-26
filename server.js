const express = require('express');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors'); // 👈 CORS સિક્યોરિટી ટૂલ ઉમેર્યું

const app = express();

app.use(cors()); // 👈 આ લાઈન ફ્રન્ટએન્ડ અને બેકએન્ડ વચ્ચેનું કનેક્શન પાકું કરશે
app.use(helmet());
app.use(express.json());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: "Too many attempts. Please try again later." }
});

const usersDB = [];

app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        const userExists = usersDB.find(u => u.email === email);
        if (userExists) return res.status(400).json({ error: "Email already registered." });

        const hashedPassword = await argon2.hash(password);
        usersDB.push({ email, password: hashedPassword });

        res.status(201).json({ success: true, message: "User registered securely!" });
    } catch (error) {
        res.status(500).json({ error: "Server error during signup." });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = usersDB.find(u => u.email === email);
        if (!user) return res.status(401).json({ error: "Invalid Credentials" });

        const validPassword = await argon2.verify(user.password, password);
        if (!validPassword) return res.status(401).json({ error: "Invalid Credentials" });

        const token = jwt.sign(
            { email: user.email }, 
            'SUPER_HEAVY_SECRET_KEY_123_@#$', 
            { expiresIn: '1h' }
        );

        res.status(200).json({ success: true, token, message: "Logged in securely!" });
    } catch (error) {
        res.status(500).json({ error: "Server error during login." });
    }
});

app.listen(3000, () => console.log('🛡️ Heavy Security Server running on port 3000'));
