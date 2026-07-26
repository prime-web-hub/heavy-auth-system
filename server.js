const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors()); 

const usersStore = []; 
const otpStore = {}; 

// ⚠️ जरूरी काम: यहाँ अपनी असली Gmail आईडी और 'App Password' सेट करें
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'YOUR_GMAIL@gmail.com',         // अपनी असली जीमेल आईडी लिखें
        pass: 'YOUR_GMAIL_APP_PASSWORD'     // गूगल से जनरेट किया हुआ 16 अक्षरों का App Password
    }
});

// 1. साइनअप एंडपॉइंट
app.post('/signup', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "सभी फ़ील्ड ज़रूरी हैं।" });

    const userExists = usersStore.find(u => u.email === email);
    if (userExists) return res.status(400).json({ error: "यह ईमेल पहले से रजिस्टर्ड है।" });

    usersStore.push({ email, password });
    res.status(201).json({ message: "अकाउंट सफलतापूर्वक बन गया है!" });
});

// 2. साधारण पासवर्ड लॉगिन एंडपॉइंट
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = usersStore.find(u => u.email === email && u.password === password);

    if (user) {
        res.json({ message: "लॉगिन सफल रहा!", token: "sample-jwt-token-123" });
    } else {
        res.status(400).json({ error: "गलत ईमेल या पासवर्ड।" });
    }
});

// 3. ईमेल पर OTP भेजने का एंडपॉइंट
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "ईमेल आईडी जरूरी है।" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = otp; 

    const mailOptions = {
        from: '"Secure Auth System" <YOUR_GMAIL@gmail.com>',
        to: email,
        subject: 'आपका लॉगिन OTP कोड',
        text: `आपका सुरक्षित लॉगिन ओटीपी (OTP) है: ${otp}. यह केवल 5 मिनट के लिए मान्य है.`
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ message: "OTP आपकी ईमेल पर भेज दिया गया है।" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "ईमेल भेजने में सर्वर में एरर आया।" });
    }
});

// 4. यूजर के OTP को वेरिफाई करने का एंडपॉइंट
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    if (otpStore[email] && otpStore[email] === otp) {
        delete otpStore[email]; 
        res.json({ message: "OTP सफलतापूर्वक वेरिफाई हो गया!", token: "sample-jwt-token-456" });
    } else {
        res.status(400).json({ error: "गलत या एक्सपायर हो चुका OTP।" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
