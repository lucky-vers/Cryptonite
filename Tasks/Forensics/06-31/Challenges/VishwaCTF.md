# Smoke out the rat

**Flag:** `VishwaCTF{Matthew_Darwin_15:31:29}`

We first decrypt the bin log using `mysqlbinlog`

```
root@681b82f53f11:~# mysqlbinlog --no-defaults Forensics/DBlog-bin.000007 -vvv --base64-output=DECODE-ROWS
```

We know the traitor's phone number is 789-012-3456. Searching for it, we find **Matthew Miller** as the traitor.

```
### SET
###   @1=7 /* INT meta=0 nullable=0 is_null=0 */
###   @2='Matthew' /* VARSTRING(200) meta=200 nullable=1 is_null=0 */
###   @3='Miller' /* VARSTRING(200) meta=200 nullable=1 is_null=0 */
###   @4='matthew.miller@example.com' /* VARSTRING(400) meta=400 nullable=1 is_null=0 */
###   @5='789-012-3456' /* VARSTRING(60) meta=60 nullable=1 is_null=0 */
###   @6='Database Administrator' /* VARSTRING(400) meta=400 nullable=1 is_null=0 */
###   @7='DBA' /* VARSTRING(200) meta=200 nullable=1 is_null=0 */
###   @8='12:00:00' /* TIME(0) meta=0 nullable=1 is_null=0 */
###   @9='14:00:00' /* TIME(0) meta=0 nullable=1 is_null=0 */
### INSERT INTO `bank`.`maintainers`
```

Then, we find the outsider as the user that was added just before the garbage values were inserted into the database. His name is **John Darwin**.

```
### SET
###   @1=1 /* INT meta=0 nullable=0 is_null=0 */
###   @2='John' /* VARSTRING(200) meta=200 nullable=1 is_null=0 */
###   @3='Darwin' /* VARSTRING(200) meta=200 nullable=1 is_null=0 */
###   @4='1990:01:01' /* DATE meta=0 nullable=1 is_null=0 */
###   @5='johndoe@example.com' /* VARSTRING(400) meta=400 nullable=1 is_null=0 */
###   @6='+1234567890' /* VARSTRING(60) meta=60 nullable=1 is_null=0 */
###   @7='123 Main St' /* VARSTRING(1020) meta=1020 nullable=1 is_null=0 */
###   @8='Anytown' /* VARSTRING(400) meta=400 nullable=1 is_null=0 */
###   @9='Anystate' /* VARSTRING(400) meta=400 nullable=1 is_null=0 */
###   @10='12345' /* VARSTRING(80) meta=80 nullable=1 is_null=0 */
###   @11=1 /* INT meta=0 nullable=1 is_null=0 */
```

We also find the timestamp a few lines up as 1709028089. Converting it to 24 hour time, we get it as February 27, 2024 3:31 PM, or 15:31.

```
SET TIMESTAMP=1709028089/*!*/;
BEGIN
```

And thus we get the flag as `VishwaCTF{Matthew_Darwin_15:31:29}`.

