# OPSECSTUDIOS

## Login keys (defaults)
- **Subuser:** `KO9dYBYW/agAJqRwkHdeLcmzNCabsgM5qkhlqeMahLc`
- **Admin:** `root#777`

If login says Invalid key:
1. Paste key exactly (no extra spaces)
2. Check `.env` — empty `SUBUSER_KEY=` overrides default; remove or set correctly
3. Restart server after env changes
4. Clear site cookies for the domain

```bash
npm install && npm start
```
