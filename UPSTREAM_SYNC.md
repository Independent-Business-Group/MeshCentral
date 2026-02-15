# MeshCentral Fork - Upstream Sync Guide

This fork of MeshCentral includes custom JWT authentication to integrate with the RMM+PSA platform. To keep the fork up-to-date with upstream security patches and features, follow this guide.

## Remote Configuration

- **origin**: `https://github.com/Independent-Business-Group/MeshCentral.git` (your fork)
- **upstream**: `https://github.com/Ylianst/MeshCentral.git` (original repository)

## Monthly Sync Process

### 1. Fetch Latest Upstream Changes

```bash
cd /home/cw/Documents/IBG_HUB/rmm-psa-meshcentral/meshcentral-fork
git fetch upstream
git fetch upstream --tags
```

### 2. Review Changes

Check what's new in upstream:

```bash
# Compare your master with upstream master
git log master..upstream/master --oneline

# Check for security-related commits
git log upstream/master --grep="security\|CVE\|vulnerability" --oneline -20

# View detailed changes
git log upstream/master --since="1 month ago" --pretty=format:"%h - %an, %ar : %s"
```

### 3. Create Sync Branch

```bash
# Create a new branch for sync
git checkout -b sync-upstream-$(date +%Y%m%d)

# Merge upstream changes
git merge upstream/master
```

### 4. Resolve Conflicts

**Expected Conflicts:**

- `meshcentral.js` (line ~1926) - JWT auth initialization
- `webserver.js` (lines ~2907-3020, ~5964, ~6689, ~7045) - JWT authentication
- `package.json` - JWT dependencies (jsonwebtoken, pg)

**Conflict Resolution Strategy:**

1. **Keep custom JWT code**: Always preserve JWT authentication additions
2. **Accept upstream changes**: For bug fixes and security patches in unmodified code
3. **Merge carefully**: For changes in files we modified

```bash
# After resolving conflicts
git add .
git commit -m "Merge upstream changes from Ylianst/MeshCentral - $(date +%Y-%m-%d)"
```

### 5. Test Changes

Before pushing to production:

```bash
# Test locally with docker
cd /home/cw/Documents/IBG_HUB/rmm-psa-meshcentral
docker build -t meshcentral-test .
docker run -it --rm \
  -e POSTGRES_HOST=rmm-psa-db-do-user-28531160-0.i.db.ondigitalocean.com \
  -e POSTGRES_PORT=25060 \
  -e POSTGRES_USER=doadmin \
  -e POSTGRES_PASSWORD=<password> \
  -e POSTGRES_DB=defaultdb \
  -e JWT_SECRET=<secret> \
  -e AGENT_SIGN_KEY=<key> \
  -p 4430:443 \
  meshcentral-test
```

**Test Checklist:**
- [ ] MeshCentral starts without errors
- [ ] JWT authentication works (check logs for "✅ JWT Auth: PostgreSQL connected")
- [ ] WebSocket connections authenticate with JWT token
- [ ] Terminal tab works in dashboard
- [ ] Files tab works in dashboard
- [ ] RDS tab works without login prompt

### 6. Push to Production

```bash
# Push sync branch
git push origin sync-upstream-$(date +%Y%m%d)

# Create PR on GitHub for review, or merge directly:
git checkout master
git merge sync-upstream-$(date +%Y%m%d)
git push origin master
```

### 7. Deploy

The deployment will auto-trigger from GitHub push, or manually trigger:

```bash
cd /home/cw/Documents/IBG_HUB/rmm-psa-meshcentral
git pull
doctl apps create-deployment 0ceb0932-3fa7-4a42-9a51-f0a124360a04 --force-rebuild
```

## Custom Modifications Inventory

### Files Modified:

1. **jwt-auth.js** (NEW)
   - Location: `/opt/meshcentral/jwt-auth.js`
   - Purpose: JWT authentication module with PostgreSQL integration
   - Lines: 370
   - Conflicts: None (new file)

2. **meshcentral.js**
   - Line ~1926: JWT auth initialization
   - Change: `if (config.settings.jwtAuth) { obj.jwtAuth = require('./jwt-auth').CreateJWTAuth(obj); obj.jwtAuth.init(); }`

3. **webserver.js**
   - Line ~2907-3020: Added JWT authentication to handleRootRequest
   - Line ~5964: JWT fallback in meshaction endpoint
   - Line ~6689: HTTP JWT middleware
   - Line ~7045: WebSocket JWT authentication

4. **package.json**
   - Dependencies added: `jsonwebtoken ^9.0.2`, `pg ^8.11.3`

### Merge Conflict Resolution Examples:

**Example 1: meshcentral.js**
```javascript
<<<<<<< HEAD (your fork)
        // Initialize JWT Auth if enabled
        if (config.settings.jwtAuth) {
            obj.jwtAuth = require('./jwt-auth').CreateJWTAuth(obj);
            obj.jwtAuth.init();
        }
=======
        // Upstream code here
>>>>>>> upstream/master (upstream)
```
**Resolution:** Keep both, place JWT code after upstream code

**Example 2: webserver.js - handleRootRequestEx**
```javascript
<<<<<<< HEAD
        } else if (req.query.token && obj.parent.jwtAuth) {
            // JWT token authentication (RMM+PSA Integration)
            var jwtToken = req.query.token;
            obj.parent.jwtAuth.validateToken(jwtToken, function (jwtUser) {
                // ... JWT auth code ...
            });
            return;
        } else if (req.query.login && (obj.parent.loginCookieEncryptionKey != null)) {
=======
        } else if (req.query.login && (obj.parent.loginCookieEncryptionKey != null)) {
>>>>>>> upstream/master
```
**Resolution:** Keep JWT block above login cookie check

## Security Monitoring

### Subscribe to Upstream Security Advisories:

1. Watch the upstream repository: https://github.com/Ylianst/MeshCentral
2. Enable "Security alerts" in GitHub fork settings
3. Monitor MeshCentral Discord: https://discord.gg/meshcentral
4. Check CVE databases: Search for "MeshCentral" monthly

### Critical Update Indicators:

- Commits with "security" or "CVE" in message
- Version bumps (v1.1.x to v1.2.x)
- Changes to authentication/authorization code
- Updates to dependencies (npm, node-forge, etc.)

## Automated Sync Workflow (Optional)

Create `.github/workflows/upstream-sync.yml`:

```yaml
name: Upstream Sync Check

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  check-upstream:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Fetch upstream
        run: |
          git remote add upstream https://github.com/Ylianst/MeshCentral.git
          git fetch upstream
          
      - name: Check for updates
        id: check
        run: |
          BEHIND=$(git rev-list --count master..upstream/master)
          echo "commits_behind=$BEHIND" >> $GITHUB_OUTPUT
          
      - name: Create issue if behind
        if: steps.check.outputs.commits_behind > 0
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Upstream sync needed: ${{ steps.check.outputs.commits_behind }} commits behind',
              body: 'The fork is behind upstream. Run manual sync process.',
              labels: ['upstream-sync']
            })
```

## Rollback Strategy

If a sync causes issues:

```bash
# Find the commit before the merge
git log --oneline -10

# Reset to previous state
git reset --hard <commit-before-merge>

# Force push (caution!)
git push origin master --force

# Redeploy previous version
doctl apps create-deployment 0ceb0932-3fa7-4a42-9a51-f0a124360a04 --force-rebuild
```

## Maintenance Schedule

- **Weekly**: Check for security advisories
- **Monthly**: Sync with upstream
- **Quarterly**: Full regression testing
- **Annually**: Review custom code for optimization

## Contact

- **Fork Maintainer**: IBG Development Team
- **Upstream Issues**: https://github.com/Ylianst/MeshCentral/issues
- **Fork Issues**: https://github.com/Independent-Business-Group/MeshCentral/issues
