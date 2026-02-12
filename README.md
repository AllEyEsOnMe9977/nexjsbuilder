## Quick Install (master branch)

```bash
rm -rf nexjsbuilder && \
git clone --branch master --single-branch https://github.com/AllEyEsOnMe9977/nexjsbuilder.git && \
cd nexjsbuilder && \
[ -f setup.sh ] || { echo "Error: setup.sh missing"; exit 1; } && \
chmod +x setup.sh && \
./setup.sh
```
