# Publish this repository on GitHub

## 1. Create an empty repository

1. Sign in to GitHub.
2. Select **New repository**.
3. Use a repository name such as `cyberbench-verifier`.
4. Choose **Public** or **Private**.
5. Do not add a README, `.gitignore` or license during creation because this folder already
   contains the required project files.
6. Create the repository and copy its HTTPS URL.

## 2. Create clean local history

Open PowerShell and run:

```powershell
cd "C:\path\to\cyberbench-verifier-public"

git init
git branch -M main

git config user.name "Silky Garg"
git config user.email "YOUR_GITHUB_NOREPLY_EMAIL"

git add .
git status
git commit -m "Initial public release"
```

Use the no-reply address shown under **GitHub → Settings → Emails**. This prevents a work
email address from appearing in public commit metadata.

## 3. Connect and upload

Replace the URL below with the empty repository URL copied from GitHub:

```powershell
git remote add origin https://github.com/YOUR_USERNAME/cyberbench-verifier.git
git push -u origin main
```

If Git asks for authentication, complete the browser sign-in or use a personal access token.

## 4. Check the public page

Confirm that:

- The README appears correctly.
- Only the files shown by `git status` were uploaded.
- No `data`, `.env`, `.venv`, `artifacts`, cache or spreadsheet files are present.
- The repository has no earlier commit history.
- The Actions or test workflow, if added later, uses only synthetic test data.
