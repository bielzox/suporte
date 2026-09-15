const fs = require('fs');
const bcrypt = require('bcryptjs');
const DB_FILE = './database.json';

async function hashAdminPassword() {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    const hashed = await bcrypt.hash('newtestpassword456', 10);
    db.admins['testadmin@example.com'].password = hashed;
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    console.log('Admin password hashed successfully');
}

hashAdminPassword().catch(console.error);
