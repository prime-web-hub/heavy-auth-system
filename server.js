// 🛡️ ENTERPRISE LEVEL STRONG SECURITY LOGIN SYSTEM
const express = require('express');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ૧. સુરક્ષા માટે હેલ્મેટ (Helmet) સિક્યોરિટી headers
app.use(helmet());
app.use(express.json());

// ૨. હેકર્સને રોકવા માટે રેટ લિમિટર (૧૫ મિનિટમાં માત્ર ૧૦૦ ટ્રાય કરી શકાશે)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: "Too many attempts. Please try again later." }
});

// યુઝર્સનો ડેટા સાચવવા માટે નકલી ડેટાબેઝ
const usersDB = [];

// ---------------------------------------------------------
// 🚀 ૧. SIGNUP CODE (નવું એકાઉન્ટ બનાવવા માટે)
// ---------------------------------------------------------
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        // ઈમેલ પેહેલાથી રજીસ્ટર છે કે નહીં તે ચેક કરવું
        const userExists = usersDB.find(u => u.email === email);
        if (userExists) return res.status(400).json({ error: "Email already registered." });

        // Argon2 દ્વારા પાસવર્ડને સુપર-સ્ટ્રોંગ હેશ (Encrypt) કરવો
        const hashedPassword = await argon2.hash(password);

        // ડેટાબેઝમાં સુરક્ષિત રીતે સેવ કરવો
        usersDB.push({ email, password: hashedPassword });

        res.status(201).json({ success: true, message: "User registered securely!" });
    } catch (error) {
        res.status(500).json({ error: "Server error during signup." });
    }
});

// ---------------------------------------------------------
// 🔑 ૨. LOGIN CODE (એકાઉન્ટ ખોલવા માટે)
// ---------------------------------------------------------
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // યુઝરને ડેટાબેઝમાં શોધવો
        const user = usersDB.find(u => u.email === email);
        if (!user) return res.status(401).json({ error: "Invalid Credentials" }); // સેફ મેસેજ

        // પાસવર્ડ સાચો છે કે નહીં તે વેરિફાય કરવું (Argon2 Verify)
        const validPassword = await argon2.verify(user.password, password);
        if (!validPassword) return res.status(401).json({ error: "Invalid Credentials" });

        // સિક્યોર JWT ટોકન બનાવવું જે ૧ કલાકમાં એક્સપાયર થઈ જશે
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

// સર્વરને પોર્ટ 3000 પર ચાલુ કરવું
app.listen(3000, () => console.log('🛡️ Heavy Security Server running on port 3000'));
