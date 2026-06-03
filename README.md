# Zenflow Android App

Flow through your goals — habit tracker for Android.

## How to get your APK (3 steps)

### Step 1 — Create a GitHub repo
1. Go to [github.com/new](https://github.com/new)
2. Name it `zenflow-android`, keep it **Public**
3. Click **Create repository**

### Step 2 — Upload this folder
On the new empty repo page, click **"uploading an existing file"** and drag the entire contents of this folder in. Commit to `main`.

> Or if you have Git installed:
> ```bash
> git init
> git add .
> git commit -m "Initial commit"
> git remote add origin https://github.com/YOUR_USERNAME/zenflow-android.git
> git push -u origin main
> ```

### Step 3 — Download your APK
1. Go to your repo on GitHub
2. Click the **Actions** tab — you'll see the build running (takes ~3 minutes)
3. When it turns green ✅, click **Releases** on the right sidebar
4. Download **Zenflow.apk**

### Install on Android
1. Send the APK to your phone (WhatsApp, email, Drive — anything)
2. Open it on your phone
3. If prompted: **Settings → Security → Allow from this source**
4. Tap **Install** — done!

---

## Project structure
```
app/src/main/
├── java/com/zenflow/app/MainActivity.java   # WebView wrapper
├── assets/
│   ├── index.html                           # App shell
│   └── app.js                               # Full React app
├── res/                                     # Icons, layouts, styles
└── AndroidManifest.xml
.github/workflows/build-apk.yml             # Auto-build pipeline
```
