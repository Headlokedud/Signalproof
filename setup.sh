#!/bin/bash
# SignalProof phone setup.
# 1) In the Codespace file explorer: long-press -> Upload... and upload BOTH
#    signalproof.zip and this file (setup.sh).
# 2) In the terminal, type just:   bash setup.sh
set -e

if [ ! -f signalproof.zip ]; then
  echo "signalproof.zip not found here - upload it first, then run: bash setup.sh"
  exit 1
fi

unzip -o -q signalproof.zip
cp -a signalproof/. .
rm -rf signalproof signalproof.zip

# keep local secret files out of git forever
grep -qx "SECRET.txt" .gitignore 2>/dev/null || echo "SECRET.txt" >> .gitignore
grep -qx "WEBHOOK_URL.txt" .gitignore 2>/dev/null || echo "WEBHOOK_URL.txt" >> .gitignore

git add -A
git commit -m "SignalProof v0.1" >/dev/null || true
git push

# generate the webhook secret into a file you can copy from the editor
openssl rand -hex 24 > SECRET.txt

echo ""
echo "=================================================="
echo "DONE - code is pushed to GitHub."
echo ""
echo "Your secret is in SECRET.txt:"
echo "  tap it in the file explorer, long-press the text,"
echo "  Select All, Copy."
echo "Paste it into Railway as the SP_SECRET variable."
echo "=================================================="
