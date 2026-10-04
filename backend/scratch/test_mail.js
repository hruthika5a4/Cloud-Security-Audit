require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

async function testEmail() {
    console.log('Testing email with:', process.env.SMTP_USER);
    try {
        const info = await transporter.sendMail({
            from: `"AuditScope Test" <${process.env.SMTP_USER}>`,
            to: process.env.SMTP_USER, // Send to self
            subject: "AuditScope SMTP Test",
            text: "Direct SMTP test from backend script.",
        });
        console.log('✅ Email sent successfully!', info.messageId);
    } catch (err) {
        console.error('❌ Email failed:', err.message);
    }
}

testEmail();
