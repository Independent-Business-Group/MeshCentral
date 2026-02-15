#!/bin/bash

# MeshCentral Fork - Upstream Sync Script
# Usage: ./sync-upstream.sh [check|merge|push]

set -e

REPO_DIR="/home/cw/Documents/IBG_HUB/rmm-psa-meshcentral/meshcentral-fork"
BRANCH_NAME="sync-upstream-$(date +%Y%m%d)"

cd "$REPO_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_upstream() {
    echo -e "${YELLOW}📡 Fetching upstream changes...${NC}"
    git fetch upstream
    git fetch upstream --tags
    
    echo -e "\n${YELLOW}📊 Comparing with upstream...${NC}"
    BEHIND=$(git rev-list --count master..upstream/master)
    
    if [ "$BEHIND" -eq 0 ]; then
        echo -e "${GREEN}✅ Fork is up-to-date with upstream!${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}⚠️  Fork is $BEHIND commits behind upstream${NC}\n"
    
    echo -e "${YELLOW}Recent upstream changes:${NC}"
    git log master..upstream/master --oneline --max-count=10
    
    echo -e "\n${YELLOW}Security-related commits:${NC}"
    git log upstream/master --grep="security\|CVE\|vulnerability" --oneline --max-count=5
    
    echo -e "\n${YELLOW}To merge these changes, run: $0 merge${NC}"
}

merge_upstream() {
    echo -e "${YELLOW}🔀 Creating sync branch: $BRANCH_NAME${NC}"
    
    # Make sure we're on master
    git checkout master
    git pull origin master
    
    # Create sync branch
    git checkout -b "$BRANCH_NAME"
    
    echo -e "${YELLOW}🔀 Merging upstream/master...${NC}"
    
    if git merge upstream/master --no-edit; then
        echo -e "${GREEN}✅ Merge successful!${NC}"
        echo -e "\n${YELLOW}📝 Custom files that may need review:${NC}"
        git diff --name-only master origin/master | grep -E "(jwt-auth|meshcentral\.js|webserver\.js|package\.json)" || echo "  (none)"
        
        echo -e "\n${GREEN}Next steps:${NC}"
        echo "1. Review changes: git log master..HEAD"
        echo "2. Test locally"
        echo "3. Push: $0 push"
    else
        echo -e "${RED}❌ Merge conflicts detected!${NC}"
        echo -e "\n${YELLOW}Conflicts in:${NC}"
        git status --short | grep "^UU"
        
        echo -e "\n${YELLOW}Resolution guide:${NC}"
        echo "1. Resolve conflicts manually (see UPSTREAM_SYNC.md)"
        echo "2. Stage resolved files: git add <file>"
        echo "3. Complete merge: git commit"
        echo "4. Push: $0 push"
        exit 1
    fi
}

push_changes() {
    CURRENT_BRANCH=$(git branch --show-current)
    
    if [[ "$CURRENT_BRANCH" != sync-upstream-* ]]; then
        echo -e "${RED}❌ Not on a sync branch. Current branch: $CURRENT_BRANCH${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}⬆️  Pushing $CURRENT_BRANCH to origin...${NC}"
    git push origin "$CURRENT_BRANCH"
    
    echo -e "${GREEN}✅ Pushed to origin!${NC}"
    echo -e "\n${YELLOW}Next steps:${NC}"
    echo "1. Create PR on GitHub for review"
    echo "2. Or merge directly: git checkout master && git merge $CURRENT_BRANCH && git push origin master"
    echo "3. Deploy: doctl apps create-deployment 0ceb0932-3fa7-4a42-9a51-f0a124360a04 --force-rebuild"
}

case "${1:-check}" in
    check)
        check_upstream
        ;;
    merge)
        merge_upstream
        ;;
    push)
        push_changes
        ;;
    *)
        echo "Usage: $0 [check|merge|push]"
        echo ""
        echo "  check  - Check for upstream updates (default)"
        echo "  merge  - Merge upstream changes into a new branch"
        echo "  push   - Push sync branch to origin"
        exit 1
        ;;
esac
