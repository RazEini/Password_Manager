# Python Password Manager

מנהל סיסמאות מאובטח עם **Vault מוצפן** (JSON), כולל CLI ו‑GUI (Tkinter).

---

## תכונות

- סיסמת מאסטר → מפתח חזק (PBKDF2-HMAC-SHA256)  
- הצפנת AES-128-GCM (Fernet)  
- Vault יחיד בקובץ JSON (מוצפן כולו)  
- ממשק CLI ו‑GUI (Tkinter)  
- העתקת סיסמאות ללוח (עם `pyperclip`)  
- בדיקת חוזק סיסמה בזמן הקלדה (GUI)  

---

## בדיקת חוזק סיסמה

היישום בודק אם סיסמה מכילה:  

- מינימום 8 תווים  
- אותיות קטנות  
- אותיות גדולות  
- ספרות  
- תווים מיוחדים (`!@#$%^&*()-_=+[]{}|;:,.<>?/~``)  

ב‑GUI, בעת הקלדת סיסמה, מוצג צבע רקע ירוק אם היא חזקה, אדום אם חלשה, ורשימת החוסרים מופיעה מתחת לשדה ההקלדה.

---

## CLI – פקודות עיקריות

| פקודה | תיאור | דוגמה |
|--------|-------|--------|
| `init` | יצירת Vault חדש | `python password_manager.py init --vault myvault.json` |
| `add` | הוספה או עדכון סיסמה | `python password_manager.py add --vault myvault.json --service gmail --user raz` |
| `get` | קבלת סיסמה | `python password_manager.py get --vault myvault.json --service gmail --copy` |
| `list` | הצגת כל השירותים | `python password_manager.py list --vault myvault.json` |
| `delete` | מחיקת שירות וסיסמה | `python password_manager.py delete --vault myvault.json --service gmail` |
| `change-master` | שינוי סיסמת מאסטר | `python password_manager.py change-master --vault myvault.json` |
| `generate` | יצירת סיסמה חזקה | `python password_manager.py generate --length 24` |
| `import-csv` | ייבוא סיסמאות מקובץ CSV | `python password_manager.py import-csv --vault myvault.json --path passwords.csv` |
| `export-csv` | ייצוא סיסמאות לקובץ CSV | `python password_manager.py export-csv --vault myvault.json --path backup.csv` |

---

## GUI – תכונות

- רשימת שירותים עם פרטי שם משתמש וסיסמה  
- כפתור "Add" להוספת שירות חדש  
- כפתור "Delete" למחיקה  
- כפתור "Change Master Password" לשינוי סיסמת מאסטר  
- כפתור "Generate Password" ליצירת סיסמה חזקה  
- הצגת פרטי שירות בפאנל נפרד עם אפשרות העתקה ללוח  
- שדה סיסמה עם אפשרות להראות/להסתיר סיסמה  

---

👨‍💻 Raz Eini (2025)
