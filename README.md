# 🔐 Python Password Manager

מנהל סיסמאות מודולרי, מאובטח וקל לשימוש הכולל ממשק CLI מקצועי, כיסוי בדיקות (Tests) מלא ו-CI/CD.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![CLI](https://img.shields.io/badge/CLI-Executable-brightgreen)
![Encryption](https://img.shields.io/badge/Encryption-AES--128--GCM-red)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 🚀 תכונות עיקריות

* **ארכיטקטורה מודולרית:** הפרדה מלאה בין לוגיקה קריפטוגרפית (`core`) לבין ממשקי המשתמש (`cli` / `gui`).
* **אבטחה חזקה:** גזירת מפתחות באמצעות PBKDF2-HMAC-SHA256 (עם 390,000 איטרציות ברירת מחדל) והצפנת AES-128-GCM (Fernet).
* **אחסון מוצפן מקומית:** הכספת (Vault) נשמרת בקובץ מוצפן יחיד (`vault.json`).
* **CLI Shortcut ייעודי:** הרצת הפקודה `passmgr` ישירות מהטרמינל.
* **אינטגרציה ללוח (Clipboard):** העתקת סיסמאות מהירה בלחיצת כפתור או דרך דגל ב-CLI (עם `pyperclip`).
* **בדיקות ו-CI/CD:** כיסוי בדיקות יחידה ב-`pytest` והרצה אוטומטית דרך GitHub Actions.

---

## 📦 התקנה והרצה

1. **שכפול הרפוזיטורי:**
   ```bash
   git clone https://github.com/your-username/password_manager.git
   cd password_manager
   ```

2. **התקנת החבילה במצב פיתוח (Editable mode):**
   ```bash
   pip install -e .
   ```

3. **הרצת בדיקות יחידה (Unit Tests):**
   ```bash
   pytest
   ```

---

## 💻 CLI – פקודות עיקריות (`passmgr`)

| פקודה | תיאור | דוגמה |
| :--- | :--- | :--- |
| `init` | יצירת Vault מוצפן חדש | `passmgr init --vault myvault.json` |
| `add` | הוספה או עדכון של סיסמה לשירות | `passmgr add --service github --user myusername` |
| `get` | שליפת סיסמה (ואפשרות העתקה ללוח) | `passmgr get --service github --copy` |
| `list` | הצגת כל השירותים הקיימים בכספת | `passmgr list` |
| `delete` | מחיקת רשומה מהכספת | `passmgr delete --service github` |
| `change-master` | שינוי סיסמת מאסטר והצפנה מחדש | `passmgr change-master` |
| `generate` | יצירת סיסמה אקראית וחזקה | `passmgr generate --length 20` |
| `export-csv` | ייצוא סיסמאות לקובץ CSV | `passmgr export-csv --path backup.csv` |
| `import-csv` | ייבוא סיסמאות מקובץ CSV | `passmgr import-csv --path backup.csv` |

---

## 🛡️ אבטחה וגזירת מפתחות

היישום אינו שומר את סיסמת המאסטר בדיסק באף שלב. המפתח הקריפטוגרפי נגזר בזמן אמת מתוך סיסמת המאסטר וה-Salt הדינמי המאוחסן בקובץ ה-Vault.

---

## 📄 רישיון

הפרויקט מופץ תחת רישיון **MIT** – חופשי לשימוש, שינוי והפצה. למידע נוסף ראה את קובץ [LICENSE](LICENSE).

---

**👨‍💻 Raz Eini**
