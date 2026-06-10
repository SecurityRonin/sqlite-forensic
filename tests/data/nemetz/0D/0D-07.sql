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
	(50001, 'Minna', 'Otto', 189454532, -4080344894.47267),
	(50002, 'Robert', 'Schmidt', 585276523, -230507764.60697),
	(50003, 'Martin', 'Otto', -604847939, 4384135040.16778),
	(50004, 'Marc', 'Meyer', 78822387, -4000459569.04090),
	(50005, 'Albert', 'Hartmann', -240257552, -3127441437.97431),
	(50006, 'Maximilian', 'Koch', -643574052, -4923448804.73029),
	(50007, 'Helena', 'Frank', 167014486, -2476882826.29330),
	(50008, 'Matthias', 'Klein', 875231645, 4161552884.22552),
	(50009, 'Jessica', 'Fuchs', -62087723, 893248597.11027),
	(50010, 'Jörg', 'Frank', -99439999, 3613359550.29976);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Erich', 'Fuchs', 83948790, -3660558494.11551),
	(20002, 'Georg', 'Schulz', 187334653, -3219345877.04919),
	(20003, 'Kurt', 'Schubert', 512133749, -2356856343.03692),
	(20004, 'Luca', 'Schumacher', 208660881, -1888520515.93760),
	(20005, 'Leni', 'Weiß', 1003869612, -441060725.33925),
	(20006, 'Ben', 'Lange', 820573069, 1515665071.32522),
	(20007, 'Kai', 'Lange', 568579181, 305373345.17826),
	(20008, 'Walter', 'Vogt', -373875935, -2207341770.27240),
	(20009, 'Karsten', 'Wolff', -1690296558, -4280308908.44777),
	(20010, 'Friedrich', 'Kraus', -102060153, 4227449223.03942);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM members where mid == 20002;
DELETE FROM members where mid == 20009;
DELETE FROM members where mid == 20003;
DELETE FROM members where mid == 20006;
DELETE FROM members where mid == 20004;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50011, 'Nils', 'Bauer', -471025150, 4678408391.62395),
	(50012, 'Adrian', 'Schmidt', 390779782, 291425141.17594),
	(50013, 'Johannes', 'Fuchs', -148205681, -3639203397.85479),
	(50014, 'Melanie', 'Koch', -62377332, -3409151541.25968),
	(50015, 'Pia', 'Stein', -911838143, -4346403777.29498);

