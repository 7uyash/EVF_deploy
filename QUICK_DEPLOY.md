# 🚀 Quick Deploy Guide (5 Minutes)

## Easiest Option: Railway (Recommended)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/email-verifier.git
git push -u origin main
```

### Step 2: Deploy Backend
1. Go to [railway.app](https://railway.app) and sign up
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Railway auto-detects Python
5. Set **Root Directory** to `backend`
6. Add environment variable: `PORT=8000`
7. Deploy! ✅

### Step 3: Deploy Frontend
1. In same Railway project, click "New Service"
2. Select "Deploy from GitHub repo" (same repo)
3. Set **Root Directory** to `frontend`
4. Set **Build Command**: `npm install && npm run build`
5. Add environment variable: `REACT_APP_API_URL=https://YOUR-BACKEND-URL.railway.app`
6. Deploy! ✅

### Step 4: Get Your URLs
- Backend URL: `https://your-backend.railway.app`
- Frontend URL: `https://your-frontend.railway.app`

**Done!** 🎉

---

## Alternative: Render (Also Free)

### Backend
1. Go to [render.com](https://render.com)
2. "New +" → "Web Service"
3. Connect GitHub repo
4. Settings:
   - Root Directory: `backend`
   - Build: `pip install -r requirements.txt`
   - Start: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Deploy!

### Frontend
1. "New +" → "Static Site"
2. Connect same repo
3. Settings:
   - Root Directory: `frontend`
   - Build: `npm install && npm run build`
   - Publish: `build`
4. Add env: `REACT_APP_API_URL=https://your-backend.onrender.com`
5. Deploy!

---

## Need Help?
See full guide in `DEPLOYMENT.md`

