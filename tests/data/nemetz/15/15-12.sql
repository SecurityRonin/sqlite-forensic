PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'random_int' INTEGER,
	'plz' INTEGER NULL,
	'small_neg' INTEGER NULL,
	'huge_number' INTEGER,
	'anyfloat' FLOAT,
	'id' INT UNSIGNED NOT NULL
);

INSERT INTO 'users' 
	(name, surname, random_int, plz, small_neg, huge_number, anyfloat, id)
	VALUES
	('Albert', 'Albrecht', 1672324, '91242', -77, 339180144, 60.06363, 20001),
	('Oliver', 'Sommer', 1172442, '67685', -112, 412028766, 50.47595, 20002),
	('Stefan', 'Haas', 1489378, '86874', -49, 317889339, 11.21666, 20003),
	('Greta', 'Peters', 228768, '94447', -17, 206622995, 4.07982, 20004),
	('Tanja', 'Krüger', 1084114, '95152', -53, 251287308, 86.35705, 20005),
	('Anton', 'Wolff', 976138, '91592', -97, 129715797, -24.06827, 20006),
	('Mike', 'Thomas', 176052, '75248', -10, 433085764, -18.71627, 20007),
	('Karsten', 'Köhler', 1950003, '86465', -118, 135754003, 60.82965, 20008),
	('Björn', 'Klein', 432730, '1458', -95, 403368585, 137.76720, 20009),
	('Emma', 'Engel', 1494162, '38559', -15, 194059912, -101.27510, 20010),
	('Sven', 'Huber', 1164378, '76846', -21, 368085755, -61.44881, 20011),
	('Erna', 'Maier', 1465567, '82380', -106, 383113740, -0.79400, 20012),
	('Sarah', 'Schuster', 400238, '97274', -20, 266593516, 147.79261, 20013),
	('Till', 'Friedrich', 1903733, '25885', -39, 379578760, -15.27605, 20014),
	('Johannes', 'Werner', 1222993, '45883', -30, 177473971, 149.68051, 20015),
	('Jens', 'Vogel', 588212, '7619', -45, 110755483, -41.26018, 20016),
	('Fabian', 'Schröder', 1719639, '22607', -65, 123975306, -130.13382, 20017),
	('Matteo', 'Lehmann', 117726, '74243', -79, 104291472, 83.08256, 20018),
	('Victoria', 'Schneider', 452044, '50679', -78, 435007151, 69.27004, 20019),
	('Sonja', 'Baumann', 1459671, '38707', -108, 109576327, 132.32515, 20020);

