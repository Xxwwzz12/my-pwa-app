const fs = require('fs');
const path = require('path');

module.exports = (req, res) => {
    try {
        const manifestPath = path.join(__dirname, '..', 'update-manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        const clientVersion = req.query.v;
        
        const updateAvailable = manifest.version !== clientVersion;
        
        res.json({
            update_available: updateAvailable,
            current_version: manifest.version,
            release_date: manifest.release_date,
            changelog: manifest.changelog.ru
        });
    } catch (error) {
        res.status(500).json({ error: "Ошибка проверки обновлений" });
    }
};