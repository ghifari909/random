# UPLODER V2 PariBtz

Sebuah aplikasi uploader canggih versi 2 yang dikembangkan oleh Parobotz untuk mengelola dan berbagi file dengan mudah.

Fitur Utama

· 📤 Upload file multiple dengan drag & drop
· 🌐 Dukungan berbagai jenis file (gambar, video, dokumen)
· 🔗 Bagikan link file dengan mudah
· 🔐 Opsi keamanan dan privasi file
· 📊 Dashboard manajemen file yang intuitif
· ⚡ Performa tinggi dengan teknologi terbaru

Teknologi yang Digunakan

· Frontend: React.js, Tailwind CSS
· Backend: Node.js, Express.js
· Database: MongoDB
· Penyimpanan: Cloud Storage (AWS S3 / Google Cloud Storage)
· Autentikasi: JWT

Persyaratan Sistem

· Node.js 16.0 atau lebih tinggi
· npm atau yarn
· MongoDB 4.0 atau lebih tinggi
· Akses ke layanan cloud storage (opsional)

Instalasi

1. Clone repository ini:

```bash
git clone https://github.com/parobotz/uploaderv2.git
cd uploaderv2
```

1. Install dependencies:

```bash
# Menggunakan npm
npm install

# atau menggunakan yarn
yarn install
```

1. Konfigurasi environment variables: Buat file.env di root directory dan sesuaikan dengan konfigurasi Anda:

```env
NEXT_PUBLIC_GITHUB_REPO=username/repo
NEXT_PUBLIC_UPLOADS_DIR=uploads
GITHUB_REPO=username/repo
GITHUB_TOKEN= (isi new token)
UPLOADS_DIR=uploads
```

1. Jalankan aplikasi:

```bash
# Development mode
npm run dev

# Production mode
npm start
```

Penggunaan

1. Buka browser dan akses http://localhost:3000
2. Login atau daftar akun baru
3. Gunakan drag & drop atau klik untuk memilih file yang akan diupload
4. Atur pengaturan privasi file (public/private)
5. Klik tombol upload dan tunggu hingga proses selesai
6. Salin link file yang telah diupload untuk dibagikan

API Endpoints

Autentikasi

· POST /api/auth/register - Mendaftar pengguna baru
· POST /api/auth/login - Login pengguna
· GET /api/auth/me - Mendapatkan informasi pengguna yang sedang login

File Management

· POST /api/files/upload - Upload file baru
· GET /api/files - Mendapatkan daftar file pengguna
· GET /api/files/:id - Mendapatkan detail file
· DELETE /api/files/:id - Menghapus file
· GET /api/files/download/:id - Mendownload file

Kontribusi

Kami menyambut kontribusi dari komunitas! Silakan ikuti langkah-langkah berikut:

1. Fork project ini
2. Buat branch fitur Anda (git checkout -b feature/AmazingFeature)
3. Commit perubahan Anda (git commit -m 'Add some AmazingFeature')
4. Push ke branch (git push origin feature/AmazingFeature)
5. Buat Pull Request

Lisensi

Distributed under the MIT License. Lihat LICENSE untuk informasi lebih lanjut.

Kontak

Parobotz - @paribotz - info@paribotz.com

Link Project: https://github.com/parobtz/uploaderv2

Dukungan

Jika Anda mengalami masalah atau memiliki pertanyaan, silakan buat issue di GitHub atau hubungi kami di info@parobotz.com.
