## Quick Install (master branch)

```bash
if [ -d nexjsbuilder/.git ]; then
  echo "Repo exists, updating..." && \
  cd nexjsbuilder && \
  git fetch origin master && \
  git checkout master && \
  git reset --hard origin/master
else
  echo "Repo not found, cloning..." && \
  git clone --branch master --single-branch https://github.com/AllEyEsOnMe9977/nexjsbuilder.git && \
  cd nexjsbuilder
fi && \
[ -f setup.sh ] || { echo "Error: setup.sh missing"; exit 1; } && \
chmod +x setup.sh && \
./setup.sh
```
