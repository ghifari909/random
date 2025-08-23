const express = require('express');
const multer = require('multer');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Load environment variables manually jika dotenv bermasalah
try {
  require('dotenv').config();
} catch (e) {
  console.log('Dotenv not available, using process.env');
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Konfigurasi multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = './uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024
  }
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Tidak ada file yang diunggah' });
    }

    // Validasi environment variables
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    if (!GITHUB_TOKEN) {
      return res.status(500).json({ error: 'Token GitHub tidak dikonfigurasi' });
    }

    const octokit = new Octokit({ auth: GITHUB_TOKEN });

    const fileContent = fs.readFileSync(req.file.path);
    const encodedContent = fileContent.toString('base64');
    
    const owner = process.env.GITHUB_OWNER || 'username';
    const repo = process.env.GITHUB_REPO || 'repo-name';
    const filePath = `uploads/${req.file.originalname}`;
    
    const response = await octokit.repos.createOrUpdateFileContents({
      owner,
      repo,
      path: filePath,
      message: `Upload file: ${req.file.originalname}`,
      content: encodedContent,
    });
    
    const fileUrl = response.data.content.html_url;
    fs.unlinkSync(req.file.path);
    
    res.json({
      message: 'File berhasil diunggah ke GitHub',
      url: fileUrl,
      filename: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype
    });
    
  } catch (error) {
    console.error('Error:', error);
    
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ 
      error: 'Gagal mengunggah file',
      details: error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});