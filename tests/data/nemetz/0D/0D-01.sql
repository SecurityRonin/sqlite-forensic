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

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20001, 'Clara', 'Klein', 48947436, 1293810450.60875),
	(20002, 'Alexandra', 'Berger', 931846220, -820077986.37267),
	(20003, 'Till', 'Groß', -85515699, 3486048746.14908),
	(20004, 'Anja', 'Frank', -754954629, 416666262.51147),
	(20005, 'Sven', 'Peters', 1607499694, -1822253683.03352),
	(20006, 'Franz', 'Thomas', -88881456, 1337095371.60448),
	(20007, 'Walter', 'Thomas', 87530326, 3127699614.56195),
	(20008, 'Marc', 'Wolf', 1735115480, 4818407860.50000),
	(20009, 'Georg', 'Albrecht', -1468273035, 1165567630.04771),
	(20010, 'Amelie', 'Weber', 752704024, 1605353875.36760);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20003;
DELETE FROM users where id == 20004;
DELETE FROM users where id == 20007;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20010;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20011, 'Alina', 'Hofmann', -757474640, -4307835041.22302),
	(20012, 'Lukas', 'Friedrich', 1179175223, 2626018206.41477),
	(20013, 'Daniel', 'Graf', -423320846, -4575745463.17372);

