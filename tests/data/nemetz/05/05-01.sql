PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' TEXT,
	'surname' TEXT,
	'email' TEXT
);

CREATE TRIGGER check_email BEFORE INSERT ON users 
BEGIN SELECT CASE 
	WHEN NEW.email NOT LIKE '%_@__%.__%' THEN 
	RAISE(ABORT, 'Email address with invalid format') 
	END;
END;

INSERT INTO 'users' 
	(name, surname, 'email')
	VALUES
	('Theo', 'Meyer', 'theomeyer');

INSERT INTO 'users' 
	(name, surname, 'email')
	VALUES
	('Noah', 'Schmidt', 'noah.schmidt@fau.de');

INSERT INTO 'users' 
	(name, surname, 'email')
	VALUES
	('Franz', 'Wolf', 'franzwolf.de');

