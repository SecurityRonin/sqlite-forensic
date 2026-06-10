PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE users (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'codeA' INT NULL,
	'codeB' FLOAT NULL
);

CREATE TABLE members (
	'mid' INT UNSIGNED NOT NULL,
	'mname' TEXT NOT NULL,
	'msurname' TEXT NULL,
	'mcodeA' INT NULL,
	'mcodeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50001, 'Maja', 'Lang', -979099654, 694130400.98461),
	(50002, 'Liam', 'Franke', -1026737640, 613028297.95192),
	(50003, 'Leni', 'Groß', 1643371695, -3428082023.01528),
	(50004, 'Elisabeth', 'Mayer', 289485196, 107790182.86047),
	(50005, 'Claudia', 'Brandt', 682453881, 4895471814.03985),
	(50006, 'Kurt', 'Müller', 277430878, -3213573693.39726),
	(50007, 'Elias', 'Sauer', 715668940, -2734937992.75483),
	(50008, 'Else', 'Vogel', -364818672, 1959408562.14585),
	(50009, 'Tobias', 'Brandt', 36208673, -2418977668.23833),
	(50010, 'Anna', 'Berger', -400626611, 3459240369.71258);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Gertrud', 'Busch', 1866760044, 668770743.37973),
	(20002, 'Thomas', 'Neumann', 94561521, 1099693540.53014),
	(20003, 'Hanna', 'Herrmann', -1489592963, 676806483.26725),
	(20004, 'Katharina', 'Frank', -942844261, 2099325608.97401),
	(20005, 'Christine', 'Seidel', 1666394471, 2008802563.42180),
	(20006, 'Anne', 'Böhm', -181378817, -4445543153.88461),
	(20007, 'Lukas', 'Fischer', -819379123, -2827242011.12392),
	(20008, 'Mika', 'Lehmann', -163995928, 714404175.85634),
	(20009, 'Jens', 'Fuchs', 384961186, -3658189642.54958),
	(20010, 'Jens', 'Fischer', -1182984342, -4895035023.75215);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 50007;
DELETE FROM users where id == 50010;
DELETE FROM members where mid == 20001;
DELETE FROM members where mid == 20006;
DELETE FROM users where id == 50005;
DELETE FROM members where mid == 20004;
DELETE FROM members where mid == 20002;
DELETE FROM users where id == 50003;
DELETE FROM members where mid == 20007;
DELETE FROM members where mid == 20003;
DELETE FROM users where id == 50001;
DELETE FROM users where id == 50006;
DELETE FROM members where mid == 20010;
DELETE FROM members where mid == 20005;
DELETE FROM users where id == 50004;
DELETE FROM users where id == 50002;
DELETE FROM members where mid == 20009;
DELETE FROM members where mid == 20008;
DELETE FROM users where id == 50009;
DELETE FROM users where id == 50008;

DROP TABLE users;
DROP TABLE members;
