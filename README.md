Python Password Manager - CLI Tool
==================================
ניהול סיסמאות מאובטח בעזרת קובץ Vault מוצפן.

תכונות:
--------
- סיסמת מאסטר → מפתח חזק (PBKDF2-HMAC-SHA256)
- הצפנת AES-128-GCM (Fernet)
- Vault יחיד בקובץ JSON (מוצפן כולו)
- פקודות לניהול סיסמאות: init, add, get, list, delete, change-master, generate, import-csv, export-csv
- תמיכה בהעתקה ל־Clipboard (אם מותקן pyperclip)

הוראות שימוש:
--------------

1. יצירת Vault חדש:
   python password_manager.py init --vault myvault.json
   - המערכת תבקש סיסמת מאסטר (פעמיים לאימות)
   - הקובץ יווצר ויכיל את כל הסיסמאות (בהתחלה ריק)
   - טיפ: בחר סיסמת מאסטר חזקה (לפחות 8 תווים)

2. הוספת סיסמה חדשה:
   python password_manager.py add --vault myvault.json --service gmail --user raz
   - --service : שם השירות (מזהה ייחודי)
   - --user : שם משתמש (אם לא מספקים, הקוד ישאל)
   - --notes : הערות נוספות
   - --generate : יצירת סיסמה חזקה אוטומטית
   - --length : אורך הסיסמה המיוצרת
   - --no-symbols : לא לכלול תווים מיוחדים

3. קבלת סיסמה קיימת:
   python password_manager.py get --vault myvault.json --service gmail
   - תידרש סיסמת מאסטר
   - אפשר להוסיף --copy כדי להעתיק את הסיסמה ללוח

4. רשימת כל השירותים:
   python password_manager.py list --vault myvault.json
   - מציג את כל השירותים הקיימים ב־Vault

5. מחיקת סיסמה:
   python password_manager.py delete --vault myvault.json --service gmail
   - מוחק את הסיסמה והשירות מה־Vault

6. שינוי סיסמת מאסטר:
   python password_manager.py change-master --vault myvault.json
   - המערכת תבקש סיסמה ישנה, סיסמה חדשה ואימות
   - מעדכן את כל הסיסמאות בקובץ עם הסיסמה החדשה

7. יצירת סיסמה חזקה (ללא שמירה):
   python password_manager.py generate --length 24
   - אפשר להוסיף --no-symbols כדי לא לכלול תווים מיוחדים

8. ייבוא סיסמאות מקובץ CSV:
   python password_manager.py import-csv --vault myvault.json --path passwords.csv
   - פורמט CSV חובה:
     service,username,password,notes
     example.com,alice,Very$trongP@ss,optional note
   - מעדכן או מוסיף רשומות קיימות ב־Vault

9. ייצוא סיסמאות לקובץ CSV:
   python password_manager.py export-csv --vault myvault.json --path backup.csv
   - מייצא את כל הסיסמאות לקריאה או לגיבוי

טיפים נוספים:
-------------
- תמיד הקפד לעבוד עם Vault הנכון (--vault filename.json)
- אל תפרסם או תשלח את קובץ Vault – הוא מכיל סיסמאות מוצפנות
- הוספת שירות קיים עם add יעדכן את הסיסמה הקיימת


👨‍💻 Raz Eini (2025)


