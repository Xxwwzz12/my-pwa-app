const fs = require('fs');
const path = require('path');

module.exports = (req, res) => {
    try {
        const manifestPath = path.join(__dirname, '..', 'update-manifest.json');
        
        if (!fs.existsSync(manifestPath)) {
            return res.status(404).json({ error: "Файл обновлений не найден" });
        }
        
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        const clientVersion = req.query.v || '1.0';
        
        res.json({
            update_available: manifest.version !== clientVersion,
            current_version: manifest.version,
            release_date: manifest.release_date,
            changelog: manifest.changelog.ru
        });
    } catch (error) {
        console.error('Ошибка проверки обновлений:', error);
        res.status(500).json({ error: "Ошибка сервера при проверке обновлений" });
    }
};