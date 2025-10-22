#!/bin/bash
# Script per automatizzare pull, add, commit e push su main

echo "🔄 Eseguo git pull..."
git pull origin main

echo "➕ Aggiungo i file modificati..."
git add .

# Chiede un messaggio di commit all'utente
echo "✏️ Inserisci il messaggio di commit:"
read commit_message

echo "💬 Commit in corso..."
git commit -m "$commit_message"

echo "🚀 Invio le modifiche a GitHub..."
git push origin main

echo "✅ Operazione completata con successo!"
