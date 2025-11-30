# 🚀 Free Hosting Deployment Guide

This guide covers deploying the Email Finder & Verifier application to **free hosting platforms**.

## 📋 Table of Contents

1. [Recommended Free Hosting Options](#recommended-free-hosting-options)
2. [Option 1: Railway (Easiest - Full Stack)](#option-1-railway-easiest---full-stack)
3. [Option 2: Render (Great Free Tier)](#option-2-render-great-free-tier)
4. [Option 3: Vercel + Render (Best Performance)](#option-3-vercel--render-best-performance)
5. [Option 4: Fly.io (Docker-based)](#option-4-flyio-docker-based)
6. [Environment Variables](#environment-variables)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 Recommended Free Hosting Options

### **Best Overall: Railway** ⭐
- ✅ Free tier: $5/month credit (enough for small apps)
- ✅ Easy deployment from GitHub
- ✅ Automatic HTTPS
- ✅ Can host both backend and frontend
- ✅ Simple configuration

### **Best for Frontend: Vercel** ⭐
- ✅ Completely free for React apps
- ✅ Excellent performance (CDN)
- ✅ Automatic deployments
- ✅ Easy setup

### **Best for Backend: Render**
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Good for Python/FastAPI
- ⚠️ Spins down after 15 min inactivity (free tier)

### **Alternative: Fly.io**
- ✅ Free tier: 3 shared VMs
- ✅ Docker-based deployment
- ✅ Good performance

---

## Option 1: Railway (Easiest - Full Stack)

### Prerequisites
- GitHub account
- Railway account (sign up at [railway.app](https://railway.app))

### Steps

1. **Push your code to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/email-verifier.git
   git push -u origin main
   ```

2. **Deploy Backend**
   - Go to [railway.app](https://railway.app)
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository
   - Railway will auto-detect Python
   - Set root directory to `backend/`
   - Add environment variables (see [Environment Variables](#environment-variables))
   - Railway will automatically deploy!

3. **Deploy Frontend**
   - Create a new service in the same project
   - Select "Deploy from GitHub repo"
   - Choose the same repository
   - Set root directory to `frontend/`
   - Build command: `npm install && npm run build`
   - Start command: `npm start` (or use static hosting)
   - Add environment variable: `REACT_APP_API_URL=https://your-backend-url.railway.app`

4. **Get URLs**
   - Railway provides HTTPS URLs automatically
   - Update frontend `REACT_APP_API_URL` with backend URL

---

## Option 2: Render (Great Free Tier)

### Deploy Backend

1. **Push to GitHub** (same as Railway)

2. **Create Web Service**
   - Go to [render.com](https://render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub repo
   - Settings:
     - **Name**: `email-verifier-backend`
     - **Root Directory**: `backend`
     - **Environment**: `Python 3`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Add environment variables
   - Click "Create Web Service"

3. **Deploy Frontend**
   - Click "New +" → "Static Site"
   - Connect GitHub repo
   - Settings:
     - **Root Directory**: `frontend`
     - **Build Command**: `npm install && npm run build`
     - **Publish Directory**: `build`
   - Add environment variable: `REACT_APP_API_URL=https://your-backend.onrender.com`
   - Click "Create Static Site"

**Note**: Free tier spins down after 15 min inactivity. First request may be slow.

---

## Option 3: Vercel + Render (Best Performance)

### Deploy Frontend to Vercel

1. **Install Vercel CLI** (optional, or use web interface)
   ```bash
   npm i -g vercel
   ```

2. **Deploy**
   ```bash
   cd frontend
   vercel
   ```
   Or use GitHub integration:
   - Go to [vercel.com](https://vercel.com)
   - Import your GitHub repo
   - Root directory: `frontend`
   - Build command: `npm run build`
   - Output directory: `build`
   - Add environment variable: `REACT_APP_API_URL=https://your-backend.onrender.com`

### Deploy Backend to Render
- Follow [Option 2 Backend](#deploy-backend) steps above

**Result**: Fast frontend (Vercel CDN) + Backend on Render

---

## Option 4: Fly.io (Docker-based)

### Prerequisites
- Install Fly CLI: https://fly.io/docs/getting-started/installing-flyctl/

### Steps

1. **Create Dockerfile** (see `Dockerfile` in repo)

2. **Initialize Fly.io**
   ```bash
   fly auth login
   fly launch
   ```

3. **Deploy Backend**
   ```bash
   cd backend
   fly launch
   # Follow prompts
   fly deploy
   ```

4. **Deploy Frontend**
   ```bash
   cd frontend
   fly launch
   fly deploy
   ```

---

## Environment Variables

### Backend Environment Variables

Add these in your hosting platform's environment variables section:

```bash
# Optional - Internet checks
ENABLE_INTERNET_CHECKS=true
ENABLE_HIBP=true

# Optional - API Keys (if you have them)
HIBP_API_KEY=your-key-here
GOOGLE_API_KEY=your-key-here
GOOGLE_CSE_ID=your-cse-id-here

# Optional - Sender domain for SMTP
VERIFIER_SENDER_DOMAIN=yourdomain.com

# Port (usually auto-set by platform)
PORT=8000
```

### Frontend Environment Variables

```bash
# Required - Backend API URL
REACT_APP_API_URL=https://your-backend-url.railway.app
```

---

## Quick Start Commands

### For Railway/Render (Backend)
```bash
# Build command
pip install -r requirements.txt

# Start command
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### For Frontend (Static)
```bash
# Build command
npm install && npm run build

# Output directory
build/
```

---

## Troubleshooting

### Backend Issues

**Port binding error**
- Use `--host 0.0.0.0` and `--port $PORT` (platform sets PORT)

**Import errors**
- Make sure root directory is set to `backend/`
- Check `requirements.txt` is in the right location

**SMTP timeouts**
- Some platforms may block port 25
- This is normal - verification will still work for most domains

### Frontend Issues

**API connection fails**
- Check `REACT_APP_API_URL` is set correctly
- Ensure backend URL includes `https://`
- Check CORS settings in backend (should allow all origins)

**Build fails**
- Delete `node_modules` and `package-lock.json`
- Run `npm install` locally first
- Check Node.js version (needs 16+)

### Platform-Specific

**Render (Free Tier)**
- First request after spin-down takes ~30 seconds
- This is normal for free tier

**Railway**
- Check usage in dashboard (free tier has limits)
- Upgrade if you exceed $5/month credit

---

## 🎉 After Deployment

1. **Test your backend**: `https://your-backend-url.railway.app/`
2. **Test your frontend**: `https://your-frontend-url.vercel.app`
3. **Update frontend API URL** if needed
4. **Share your app!** 🚀

---

## 📝 Notes

- **Free tiers have limitations**: Rate limits, spin-downs, resource limits
- **For production**: Consider paid plans for better performance
- **SMTP port 25**: May be blocked on some platforms (affects some verifications)
- **HTTPS**: All platforms provide free SSL certificates

---

## 🆘 Need Help?

- Railway: [docs.railway.app](https://docs.railway.app)
- Render: [render.com/docs](https://render.com/docs)
- Vercel: [vercel.com/docs](https://vercel.com/docs)
- Fly.io: [fly.io/docs](https://fly.io/docs)

