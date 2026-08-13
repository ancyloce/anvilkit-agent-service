package canonical

import "testing"

func TestDigestIsPropertyOrderIndependent(t *testing.T) {
	first, err := Digest([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest([]byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("digests differ: %s %s", first, second)
	}
}
func TestDigestUsesStrictAdmission(t *testing.T) {
	if _, err := Digest([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
