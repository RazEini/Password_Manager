<div align="right" dir="rtl">

<div align="center">

# 🔐 Python Password Manager

מנהל סיסמאות מודולרי, מאובטח וקל לשימוש הכולל ממשק CLI מקצועי, כיסוי בדיקות (Tests) מלא ו-CI/CD.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![CLI](https://img.shields.io/badge/CLI-Executable-brightgreen)
![Encryption](https://img.shields.io/badge/Encryption-AES--128--GCM-red)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256-orange) <br><br>
![License](https://img.shields.io/badge/License-MIT-blue)
![Tests](https://github.com/RazEini/Password_Manager/actions/workflows/test.yml/badge.svg)

</div>

---

## 🚀 תכונות עיקריות

* **ארכיטקטורה מודולרית:** הפרדה מלאה בין לוגיקה קריפטוגרפית (`core`) לבין ממשק ה-CLI והאחסון.
* **אבטחה חזקה:** גזירת מפתחות באמצעות PBKDF2-HMAC-SHA256 (עם 390,000 איטרציות ברירת מחדל) והצפנת AES-128-GCM (Fernet).
* **אחסון מוצפן מקומית:** הכספת (Vault) נשמרת בקובץ מוצפן יחיד (`vault.json`).
* **CLI Shortcut ייעודי:** הרצת הפקודה `passmgr` ישירות מהטרמינל.
* **אינטגרציה ללוח (Clipboard):** העתקת סיסמאות מהירה בלחיצת כפתור או דרך דגל ב-CLI (עם `pyperclip`).
* **בדיקות ו-CI/CD:** כיסוי בדיקות יחידה ב-`pytest` והרצה אוטומטית דרך GitHub Actions.

---

## 📦 התקנה והרצה

**1. שכפול הרפוזיטורי:**

</div>

```bash
git clone [https://github.com/RazEini/Password_Manager.git](https://github.com/RazEini/Password_Manager.git)
cd Password_Manager
```

<div align="right" dir="rtl">

**2. התקנת החבילה במצב פיתוח (Editable mode):**

</div>

```bash
pip install -e .
```

<div align="right" dir="rtl">

**3. הרצת בדיקות יחידה (Unit Tests):**

</div>

```bash
pytest
```

<div align="right" dir="rtl">

---

<h2 align="center">
  💻 CLI – פקודות עיקריות (`passmgr`)
</h2>

<div align="center">

<table align="center">
  <thead>
    <tr>
      <th align="center">פקודה</th>
      <th align="center">תיאור</th>
      <th align="center">דוגמה</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><code>init</code></td>
      <td align="center">יצירת Vault מוצפן חדש</td>
      <td align="left"><code>passmgr --vault myvault.json init</code></td>
    </tr>
    <tr>
      <td align="center"><code>add</code></td>
      <td align="center">הוספה או עדכון של סיסמה לשירות</td>
      <td align="left"><code>passmgr add --service github --user myusername</code></td>
    </tr>
    <tr>
      <td align="center"><code>get</code></td>
      <td align="center">שליפת סיסמה (ואפשרות העתקה ללוח)</td>
      <td align="left"><code>passmgr get --service github --copy</code></td>
    </tr>
    <tr>
      <td align="center"><code>list</code></td>
      <td align="center">הצגת כל השירותים הקיימים בכספת</td>
      <td align="left"><code>passmgr list</code></td>
    </tr>
    <tr>
      <td align="center"><code>delete</code></td>
      <td align="center">מחיקת רשומה מהכספת</td>
      <td align="left"><code>passmgr delete --service github</code></td>
    </tr>
    <tr>
      <td align="center"><code>change-master</code></td>
      <td align="center">שינוי סיסמת מאסטר והצפנה מחדש</td>
      <td align="left"><code>passmgr change-master</code></td>
    </tr>
    <tr>
      <td align="center"><code>generate</code></td>
      <td align="center">יצירת סיסמה אקראית וחזקה</td>
      <td align="left"><code>passmgr generate --length 20</code></td>
    </tr>
    <tr>
      <td align="center"><code>export-csv</code></td>
      <td align="center">ייצוא סיסמאות לקובץ CSV</td>
      <td align="left"><code>passmgr export-csv --path backup.csv</code></td>
    </tr>
    <tr>
      <td align="center"><code>import-csv</code></td>
      <td align="center">ייבוא סיסמאות מקובץ CSV</td>
      <td align="left"><code>passmgr import-csv --path backup.csv</code></td>
    </tr>
  </tbody>
</table>

</div>

---

## 🛡️ אבטחה וגזירת מפתחות

היישום אינו שומר את סיסמת המאסטר בדיסק באף שלב. המפתח הקריפטוגרפי נגזר בזמן אמת מתוך סיסמת המאסטר וה-Salt הדינמי המאוחסן בקובץ ה-Vault.

---

## 📄 רישיון

הפרויקט מופץ תחת רישיון **MIT** – חופשי לשימוש, שינוי והפצה. למידע נוסף ראה את קובץ [LICENSE](LICENSE).

---

<h4 align="center">
  👨‍💻 Raz Eini (2026)
</h4>

</div>
