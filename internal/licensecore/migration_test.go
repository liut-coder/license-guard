package licensecore

import "testing"

func TestSplitSQLStatements(t *testing.T) {
	input := `
-- leading comment with ; inside
CREATE TABLE demo (id text PRIMARY KEY, note text DEFAULT 'a;b');
INSERT INTO demo (id, note) VALUES ('one', 'it''s; ok');
/* block ; comment */
DO $$
BEGIN
  RAISE NOTICE 'hello; world';
END
$$;
`
	got := splitSQLStatements(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 statements, got %d: %#v", len(got), got)
	}
	for i, statement := range got {
		if statement == "" {
			t.Fatalf("statement %d is empty", i)
		}
	}
}
