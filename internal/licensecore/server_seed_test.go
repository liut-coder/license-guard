package licensecore

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type seedTestStore struct {
	loadData Data
	loadErr  error
	saved    Data
	saveOK   bool
}

func (s *seedTestStore) Load() (Data, error) {
	if s.loadErr != nil {
		return Data{}, s.loadErr
	}
	return s.loadData, nil
}

func (s *seedTestStore) Save(data Data) error {
	s.saved = data
	s.saveOK = true
	return nil
}

func (s *seedTestStore) Name() string {
	return "seed-test"
}

func TestNewServerWithStoreOptionsRejectsEmptyStoreWhenDemoSeedDisabled(t *testing.T) {
	store := &seedTestStore{loadErr: ErrStoreNotFound}
	_, err := NewServerWithStoreOptions(t.TempDir(), store, ServerOptions{SeedDemoData: false})
	if err == nil {
		t.Fatal("expected empty store to be rejected when demo seed is disabled")
	}
	if !strings.Contains(err.Error(), "demo seed is disabled") {
		t.Fatalf("error = %q, want demo seed disabled", err.Error())
	}
	if store.saveOK {
		t.Fatal("empty production store should not be saved with demo data")
	}
}

func TestNewServerWithStoreOptionsBootstrapsAdminWithoutDemoData(t *testing.T) {
	store := &seedTestStore{loadErr: ErrStoreNotFound}
	_, err := NewServerWithStoreOptions(t.TempDir(), store, ServerOptions{
		SeedDemoData: false,
		BootstrapAdmin: &BootstrapAdmin{
			Account:  "ops@example.com",
			Name:     "Ops Admin",
			Password: "VeryStrong123!",
		},
	})
	if err != nil {
		t.Fatalf("NewServerWithStoreOptions returned error: %v", err)
	}
	if !store.saveOK {
		t.Fatal("bootstrap should save initial data")
	}
	if len(store.saved.Admins) != 1 {
		t.Fatalf("admins = %#v, want one bootstrap admin", store.saved.Admins)
	}
	admin := store.saved.Admins[0]
	if admin.Account != "ops@example.com" || admin.Name != "Ops Admin" {
		t.Fatalf("unexpected bootstrap admin: %#v", admin)
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte("VeryStrong123!")) != nil {
		t.Fatal("bootstrap admin password hash does not match configured password")
	}
	if len(store.saved.Apps) != 0 || len(store.saved.Licenses) != 0 {
		t.Fatalf("bootstrap should not seed demo app or license: apps=%#v licenses=%#v", store.saved.Apps, store.saved.Licenses)
	}
}

func TestNewServerWithStoreOptionsRejectsLoadedStoreWithoutAdminsWhenDemoSeedDisabled(t *testing.T) {
	store := &seedTestStore{loadData: Data{
		Apps: []App{{
			ID:     "app_existing",
			AppKey: "app_existing",
			Name:   "Existing App",
			Status: "active",
		}},
	}}
	_, err := NewServerWithStoreOptions(t.TempDir(), store, ServerOptions{SeedDemoData: false})
	if err == nil {
		t.Fatal("expected store without admins to be rejected when demo seed is disabled")
	}
	if !strings.Contains(err.Error(), "has no admins") {
		t.Fatalf("error = %q, want missing admins", err.Error())
	}
}

func TestNewServerWithStoreOptionsPropagatesLoadErrors(t *testing.T) {
	wantErr := errors.New("load failed")
	store := &seedTestStore{loadErr: wantErr}
	_, err := NewServerWithStoreOptions(t.TempDir(), store, ServerOptions{SeedDemoData: false})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}
