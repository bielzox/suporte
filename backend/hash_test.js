const fs = require('fs');
const bcrypt = require('bcryptjs');
const DB_FILE = './database.json';

async function hashPassword() {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    const hashed = await bcrypt.hash('Bielzox', 10);
    db.users['bielzoxfps@gmail.com'].password = hashed;
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    console.log('Password hashed successfully');
}

hashPassword().catch(console.error);
