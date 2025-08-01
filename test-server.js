import express from 'express';

const app = express();
const PORT = 3001;

// Минимальный тестовый роут
app.get('/test', (req, res) => {
  res.send('OK');
});

app.listen(PORT, () => {
  console.log(`Test server running on http://localhost:${PORT}`);
});