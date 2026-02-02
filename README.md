<div dir="rtl">

  <h1 align="center">🔐 Python Password Manager</h1>

  <p align="center">
    מנהל סיסמאות מאובטח עם <strong>Vault מוצפן</strong> (JSON), כולל CLI ו‑GUI (Tkinter).
  </p>

  <br>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-100%25-blue?logo=python" alt="Python Badge">
    <img src="https://img.shields.io/badge/CLI-GUI-lightgrey" alt="CLI/GUI Badge">
    <img src="https://img.shields.io/badge/Encryption-AES-red" alt="Encryption Badge">
    <img src="https://img.shields.io/badge/License-MIT-blue" alt="License Badge">
  </p>

  <br/>

  <h2 align="center">🎬 Demo / המחשה</h2>

  <br/>

  <table align="center">
  <tr>
    <td align="center">
      <img src="assets/password_manager_image2.PNG" width="350" alt="מסך יצירת סיסמא לכספת" />
      <br><b>מסך יצירת סיסמא לכספת</b>
    </td>
    <td align="center">
      <img src="assets/password_manager_image1.PNG" width="350" alt="מסך כספת הסיסמאות" />
      <br><b>מסך כספת הסיסמאות</b>
    </td>
  </tr>
</table>

<br/>

  <hr>

  <h2>🚀 תכונות</h2>
  <ul>
    <li>סיסמת מאסטר → מפתח חזק (PBKDF2-HMAC-SHA256)</li>
    <li>הצפנת AES-128-GCM (Fernet)</li>
    <li>Vault יחיד בקובץ JSON (מוצפן כולו)</li>
    <li>ממשק CLI ו‑GUI (Tkinter)</li>
    <li>העתקת סיסמאות ללוח (עם <code>pyperclip</code>)</li>
    <li>בדיקת חוזק סיסמה בזמן הקלדה (GUI)</li>
  </ul>

  <hr>

  <h2>💪 בדיקת חוזק סיסמה</h2>
  <p>היישום בודק אם סיסמה מכילה:</p>
  <ul>
    <li>מינימום 8 תווים</li>
    <li>אותיות קטנות</li>
    <li>אותיות גדולות</li>
    <li>ספרות</li>
    <li>תווים מיוחדים (<code>!@#$%^&*()-_=+[]{}|;:,.&lt;&gt;?/~`</code>)</li>
  </ul>
  <p>ב‑GUI, בעת הקלדת סיסמה, מוצג צבע רקע ירוק אם היא חזקה, אדום אם חלשה, ורשימת החוסרים מופיעה מתחת לשדה ההקלדה.</p>

  <hr>

  <h2 align="center">💻 CLI – פקודות עיקריות</h2>
  <table>
    <thead>
      <tr>
        <th>פקודה</th>
        <th>תיאור</th>
        <th>דוגמה</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>init</td><td>יצירת Vault חדש</td><td><code>python password_manager.py init --vault myvault.json</code></td></tr>
      <tr><td>add</td><td>הוספה או עדכון סיסמה</td><td><code>python password_manager.py add --vault myvault.json --service gmail --user raz</code></td></tr>
      <tr><td>get</td><td>קבלת סיסמה</td><td><code>python password_manager.py get --vault myvault.json --service gmail --copy</code></td></tr>
      <tr><td>list</td><td>הצגת כל השירותים</td><td><code>python password_manager.py list --vault myvault.json</code></td></tr>
      <tr><td>delete</td><td>מחיקת שירות וסיסמה</td><td><code>python password_manager.py delete --vault myvault.json --service gmail</code></td></tr>
      <tr><td>change-master</td><td>שינוי סיסמת מאסטר</td><td><code>python password_manager.py change-master --vault myvault.json</code></td></tr>
      <tr><td>generate</td><td>יצירת סיסמה חזקה (8–64 תווים)</td><td><code>python password_manager.py generate --length 24</code></td></tr>
      <tr><td>import-csv</td><td>ייבוא סיסמאות מקובץ CSV</td><td><code>python password_manager.py import-csv --vault myvault.json --path passwords.csv</code></td></tr>
      <tr><td>export-csv</td><td>ייצוא סיסמאות לקובץ CSV</td><td><code>python password_manager.py export-csv --vault myvault.json --path backup.csv</code></td></tr>
    </tbody>
  </table>

  <hr>

  <h align="center">🖥️ GUI – תכונות</h2>
  <ul>
    <li>רשימת שירותים עם פרטי שם משתמש וסיסמה</li>
    <li>כפתור "Add" להוספת שירות חדש</li>
    <li>כפתור "Delete" למחיקה</li>
    <li>כפתור "Change Master Password" לשינוי סיסמת מאסטר</li>
    <li>כפתור "Generate Password" ליצירת סיסמה חזקה</li>
    <li>הצגת פרטי שירות בפאנל נפרד עם אפשרות העתקה ללוח</li>
    <li>שדה סיסמה עם אפשרות להראות/להסתיר סיסמה</li>
  </ul>

  <hr>

  <h2>📄 רישיון</h2>
  <p>
    הפרויקט מופץ תחת רישיון <strong>MIT</strong> – חופשי לשימוש, שינוי והפצה, כל עוד נשמר קרדיט למחבר.
  </p>
  <p>למידע נוסף ראה את קובץ <a href="LICENSE">LICENSE</a></p>

  <hr>

  <p align="center"><strong>👨‍💻 Raz Eini (2025)</strong></p>

</div>
