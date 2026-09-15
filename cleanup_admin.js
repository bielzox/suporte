const fs = require('fs');
const path = require('path');
const filePath = path.join(__dirname, 'suporte-admin.html');
let content = fs.readFileSync(filePath, 'utf8');

// Remove the garbage block between switchAdminTab and updateTime
const startMarker = '        }'; // End of switchAdminTab
const endMarker = '        /* =====================================================\n           TEMPO';

const startIndex = content.indexOf(startMarker);
const endIndex = content.indexOf(endMarker);

if (startIndex !== -1 && endIndex !== -1) {
    const before = content.substring(0, startIndex + startMarker.length);
    const after = content.substring(endIndex);
    fs.writeFileSync(filePath, before + '\n\n' + after);
    console.log('Garbage block removed successfully');
} else {
    console.error('Markers not found');
}
